package bootstrap

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/iprw/rssh/internal/token"
)

// ParseDestination splits "user@host" into user and host parts.
func ParseDestination(dest string) (user, host string) {
	if i := strings.LastIndex(dest, "@"); i >= 0 {
		return dest[:i], dest[i+1:]
	}
	return "", dest
}

// BuildSSHArgs constructs the ssh command arguments with ProxyCommand injected.
// sshFlags go before the destination, remoteCmd goes after.
func BuildSSHArgs(destination, proxyCmd string, sshFlags []string, remoteCmd []string) []string {
	args := []string{
		"-o", "ProxyCommand=" + proxyCmd,
	}
	args = append(args, sshFlags...)
	args = append(args, destination)
	args = append(args, remoteCmd...)
	return args
}

// sshFlagsWithArg lists SSH flags that consume the next argument.
var sshFlagsWithArg = map[string]bool{
	"-b": true, "-c": true, "-D": true, "-E": true, "-e": true,
	"-F": true, "-I": true, "-i": true, "-J": true, "-L": true,
	"-l": true, "-m": true, "-O": true, "-o": true, "-p": true,
	"-Q": true, "-R": true, "-S": true, "-W": true, "-w": true,
}

// Run is the main CLI entrypoint.
// It bootstraps the relay over SSH, then re-launches ssh through the WebSocket tunnel.
func Run(args []string) error {
	var (
		destination string
		sshArgs     []string // SSH flags (go before destination)
		remoteCmd   []string // remote command (goes after destination)
		noTLS       bool
		useTor      bool
		verbose     bool
		torProxy    string
		password    string
		forceProto  string // "h2" or "h3"
		vCount      int    // number of -v flags seen
	)

	torProxy = "127.0.0.1:9050"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--no-tls":
			noTLS = true
		case "--tor":
			useTor = true
		case "--verbose":
			verbose = true
		case "--tor-proxy":
			if i+1 < len(args) {
				i++
				torProxy = args[i]
			}
		case "--pass":
			if i+1 < len(args) {
				i++
				password = args[i]
			}
		case "--h2":
			forceProto = "h2"
		case "--h3":
			forceProto = "h3"
		default:
			if strings.HasPrefix(args[i], "-") {
				if args[i] == "-v" {
					vCount++
					verbose = true
					// Single -v: rssh verbose only, don't pass to SSH.
					// Two or more -v: also pass through to SSH.
					if vCount >= 2 {
						sshArgs = append(sshArgs, "-v")
					}
				} else {
					sshArgs = append(sshArgs, args[i])
					if sshFlagsWithArg[args[i]] && i+1 < len(args) {
						i++
						sshArgs = append(sshArgs, args[i])
					}
				}
			} else if destination == "" {
				destination = args[i]
			} else {
				// Everything after destination is the remote command.
				remoteCmd = append(remoteCmd, args[i:]...)
				break
			}
		}
	}

	if destination == "" {
		return fmt.Errorf("usage: rssh [--no-tls] [--tor] [-v] [ssh-flags] [user@]host [command]")
	}

	// vlogf prints only when verbose is enabled.
	vlogf := func(format string, args ...any) {
		if verbose {
			fmt.Fprintf(os.Stderr, "[rssh] "+format+"\n", args...)
		}
	}

	_, host := ParseDestination(destination)

	vlogf("destination=%s host=%s noTLS=%v tor=%v", destination, host, noTLS, useTor)
	if len(sshArgs) > 0 {
		vlogf("ssh flags: %v", sshArgs)
	}
	if len(remoteCmd) > 0 {
		vlogf("remote command: %v", remoteCmd)
	}

	// Generate session token
	tok, err := token.Generate()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	// Password handling:
	//   --pass flag: use directly, bypass key auth
	//   No --pass:   install a recording askpass so SSH tries keys first;
	//                only if keys fail does it prompt for a password (via
	//                /dev/tty), which is cached for the tunneled connection.
	var passFile string // temp file where recording askpass stores the password
	if password != "" {
		os.Setenv("RSSH_PASS", password)
		if ap, err := writeAskpassScript(); err == nil {
			os.Setenv("SSH_ASKPASS", ap)
			os.Setenv("SSH_ASKPASS_REQUIRE", "force")
			vlogf("askpass (direct): %s", ap)
		}
	} else if os.Getenv("SSHPASS") == "" && os.Getenv("RSSH_PASS") == "" {
		f, ferr := os.CreateTemp("", "rssh-passfile-*")
		if ferr == nil {
			passFile = f.Name()
			f.Close()
			os.Chmod(passFile, 0600)
			os.Setenv("RSSH_PASS_FILE", passFile)
			if ap, err := writeRecordingAskpassScript(); err == nil {
				os.Setenv("SSH_ASKPASS", ap)
				os.Setenv("SSH_ASKPASS_REQUIRE", "force")
				vlogf("askpass (recording): %s", ap)
			}
		}
	}

	// SSH multiplexing: authenticate once, reuse for all bootstrap calls.
	controlPath := fmt.Sprintf("/tmp/rssh-ctrl-%%r@%%h:%%p-%d", os.Getpid())
	controlOpts := []string{
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + controlPath,
		"-o", "ControlPersist=30",
	}
	bootstrapArgs := append(controlOpts, sshArgs...)

	// Bootstrap: SSH in, deploy relay if needed, start relay
	vlogf("bootstrapping relay on %s...", host)
	port, err := bootstrapRelay(destination, host, tok, noTLS, useTor, torProxy, bootstrapArgs)
	if err != nil {
		vlogf("bootstrap failed: %v", err)
		fmt.Fprintf(os.Stderr, "[rssh] tunnel unavailable, using plain ssh (no reconnection protection)\n")
		// Clean up passFile — fallback SSH will prompt interactively.
		if passFile != "" {
			os.Remove(passFile)
			os.Unsetenv("RSSH_PASS_FILE")
		}
		var fallback []string
		if useTor {
			fallback = append(fallback, "-o", fmt.Sprintf("ProxyCommand=%s connect --proxy %s %%h %%p", selfPath(), torProxy))
		}
		fallback = append(fallback, sshArgs...)
		fallback = append(fallback, destination)
		fallback = append(fallback, remoteCmd...)
		refreshAskpass()
		return execSSH(fallback)
	}

	vlogf("relay listening on port %s", port)

	// Capture recorded password: if the bootstrap SSH prompted for a
	// password (keys failed), the recording askpass saved it to passFile.
	// Load it into RSSH_PASS so the tunneled SSH connection reuses it.
	if passFile != "" {
		if data, err := os.ReadFile(passFile); err == nil && len(data) > 0 {
			os.Setenv("RSSH_PASS", string(data))
			vlogf("captured password from recording askpass")
		}
		os.Remove(passFile)
		os.Unsetenv("RSSH_PASS_FILE")
	}

	// Build relay URL
	scheme := "https"
	if noTLS {
		scheme = "http"
	}
	connectURL := fmt.Sprintf("%s://%s:%s/connect?token=%s", scheme, host, port, tok)

	// Build ProxyCommand
	self, err := os.Executable()
	if err != nil {
		self = "rssh"
	}

	// Build proxy command: flags MUST come before the URL (positional arg)
	// because Go's flag package stops parsing after the first non-flag.
	proxyArgs := fmt.Sprintf("%s proxy", self)
	if noTLS {
		proxyArgs += " --no-tls"
	}
	if useTor {
		proxyArgs += fmt.Sprintf(" --tor-proxy %s", torProxy)
	}
	if verbose {
		proxyArgs += " --verbose"
	}
	switch forceProto {
	case "h2":
		proxyArgs += " --h2"
	case "h3":
		proxyArgs += " --h3"
	}
	proxyArgs += " " + connectURL

	vlogf("ProxyCommand: %s", proxyArgs)

	// Exec ssh with ProxyCommand
	fullArgs := BuildSSHArgs(destination, proxyArgs, sshArgs, remoteCmd)
	vlogf("exec ssh %v", fullArgs)
	refreshAskpass()
	return execSSH(fullArgs)
}

func bootstrapRelay(destination, host, tok string, noTLS, useTor bool, torProxy string, sshArgs []string) (string, error) {
	// Build --sshd from the caller's destination host and -p port.
	// Don't assume localhost — connect to exactly what was requested.
	sshdPort := "22"
	for i, arg := range sshArgs {
		if arg == "-p" && i+1 < len(sshArgs) {
			sshdPort = sshArgs[i+1]
			break
		}
	}
	sshdAddr := host + ":" + sshdPort

	relayCmd := fmt.Sprintf(
		"mkdir -p ~/.rssh && "+
			"test -x ~/.rssh/relay || { echo NEED_DEPLOY; exit 0; } && "+
			"echo RELAY_HASH $(sha256sum ~/.rssh/relay 2>/dev/null | cut -d' ' -f1) && "+
			"~/.rssh/relay relay --token %s --listen :0 --sshd %s",
		tok, sshdAddr,
	)
	if noTLS {
		relayCmd += " --no-tls"
	}

	// Forward SSH connection flags (e.g. -p, -i, -F, -J) so the
	// bootstrap connection reaches the same host as the final session.
	sshBootstrap := append([]string{}, sshArgs...)
	if useTor {
		sshBootstrap = append(sshBootstrap,
			"-o", fmt.Sprintf("ProxyCommand=%s connect --proxy %s %%h %%p", selfPath(), torProxy),
		)
	}
	sshBootstrap = append(sshBootstrap, destination, relayCmd)

	cmd := exec.Command("ssh", sshBootstrap...)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start ssh: %w", err)
	}

	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "NEED_DEPLOY" {
			// Remote already exited (exit 0). Don't SIGKILL — that
			// destroys the ControlMaster socket and breaks SCP auth.
			cmd.Wait()
			if err := deployRelay(destination, useTor, torProxy, sshArgs); err != nil {
				return "", fmt.Errorf("deploy: %w", err)
			}
			return bootstrapRelay(destination, host, tok, noTLS, useTor, torProxy, sshArgs)
		}

		// Auto-update: compare remote relay hash with local binary.
		if strings.HasPrefix(line, "RELAY_HASH ") {
			remoteHash := strings.TrimPrefix(line, "RELAY_HASH ")
			if localHash, err := localBinaryHash(); err == nil && remoteHash != "" && localHash != remoteHash {
				fmt.Fprintf(os.Stderr, "[rssh] relay outdated, updating...\n")
				cmd.Process.Signal(syscall.SIGTERM)
				cmd.Wait()
				if err := deployRelay(destination, useTor, torProxy, sshArgs); err != nil {
					return "", fmt.Errorf("deploy: %w", err)
				}
				return bootstrapRelay(destination, host, tok, noTLS, useTor, torProxy, sshArgs)
			}
			continue
		}

		// Relay prints "RSSH_PORT <port>" when ready
		if strings.HasPrefix(line, "RSSH_PORT ") {
			port := strings.TrimPrefix(line, "RSSH_PORT ")
			return port, nil
		}
	}

	waitErr := cmd.Wait()
	return "", fmt.Errorf("relay did not report port (ssh exit: %v, scanner err: %v)", waitErr, scanner.Err())
}

func deployRelay(destination string, useTor bool, torProxy string, extraSSHArgs []string) error {
	// Determine remote OS/arch — forward connection flags so scp/ssh
	// reach the same host (e.g. -p, -i, -F, -J).
	sshArgs := append([]string{}, extraSSHArgs...)
	if useTor {
		sshArgs = append(sshArgs,
			"-o", fmt.Sprintf("ProxyCommand=%s connect --proxy %s %%h %%p", selfPath(), torProxy),
		)
	}
	sshArgs = append(sshArgs, destination,
		"pkill -f '[.]rssh/relay relay' 2>/dev/null; sleep 0.3; mkdir -p ~/.rssh && uname -sm")

	out, err := exec.Command("ssh", sshArgs...).Output()
	if err != nil {
		return fmt.Errorf("detect arch: %w", err)
	}

	parts := strings.Fields(strings.TrimSpace(string(out)))
	if len(parts) < 2 {
		return fmt.Errorf("unexpected uname output: %q", string(out))
	}

	goos := strings.ToLower(parts[0])
	goarch := normalizeArch(parts[1])

	// Find local relay binary for this target
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find self: %w", err)
	}

	// Deploy relay binary by piping through the ControlMaster SSH session.
	// Uses -C for compression and atomic mv to avoid "Text file busy".
	fmt.Fprintf(os.Stderr, "[rssh] deploying relay to %s (%s/%s)...\n", destination, goos, goarch)

	deployArgs := append([]string{}, extraSSHArgs...)
	if useTor {
		deployArgs = append(deployArgs,
			"-o", fmt.Sprintf("ProxyCommand=%s connect --proxy %s %%h %%p", selfPath(), torProxy),
		)
	}
	deployArgs = append(deployArgs, "-C", destination,
		"cat > ~/.rssh/relay.tmp && chmod +x ~/.rssh/relay.tmp && mv -f ~/.rssh/relay.tmp ~/.rssh/relay")

	sshCmd := exec.Command("ssh", deployArgs...)
	sshCmd.Stderr = os.Stderr

	// Use pv for progress bar if available, otherwise pipe directly.
	if pvPath, _ := exec.LookPath("pv"); pvPath != "" {
		pvCmd := exec.Command(pvPath, self)
		pvCmd.Stderr = os.Stderr
		sshCmd.Stdin, err = pvCmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("pv pipe: %w", err)
		}
		if err := pvCmd.Start(); err != nil {
			return fmt.Errorf("pv start: %w", err)
		}
		if err := sshCmd.Run(); err != nil {
			pvCmd.Process.Kill()
			pvCmd.Wait()
			return fmt.Errorf("deploy relay: %w", err)
		}
		if err := pvCmd.Wait(); err != nil {
			return fmt.Errorf("pv: %w", err)
		}
	} else {
		binFile, err := os.Open(self)
		if err != nil {
			return fmt.Errorf("open self: %w", err)
		}
		defer binFile.Close()
		sshCmd.Stdin = binFile
		if err := sshCmd.Run(); err != nil {
			return fmt.Errorf("deploy relay: %w", err)
		}
	}

	return nil
}

// localBinaryHash returns the SHA256 hex digest of the running executable.
func localBinaryHash() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(self)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// selfPath returns the path to the running executable, falling back to "rssh".
func selfPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "rssh"
}

func normalizeArch(uname string) string {
	switch uname {
	case "x86_64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return uname
	}
}

// writeAskpassScript creates a temp shell script that echoes $RSSH_PASS.
// SSH_ASKPASS must be a path to an executable (no arguments allowed).
func writeAskpassScript() (string, error) {
	f, err := os.CreateTemp("", "rssh-askpass-*.sh")
	if err != nil {
		return "", err
	}
	f.WriteString("#!/bin/sh\nprintf '%s' \"$RSSH_PASS\"\nrm -f \"$0\"\n")
	f.Close()
	os.Chmod(f.Name(), 0700)
	return f.Name(), nil
}

// refreshAskpass writes a fresh self-deleting askpass script before execSSH.
// The bootstrap SSH auth may have already consumed (and self-deleted) the
// original script, so the tunneled SSH session needs a new one.
func refreshAskpass() {
	if os.Getenv("RSSH_PASS") == "" {
		return
	}
	ap, err := writeAskpassScript()
	if err != nil {
		return
	}
	os.Setenv("SSH_ASKPASS", ap)
}

// writeRecordingAskpassScript creates a temp shell script that prompts the
// user on /dev/tty and records the entered password to $RSSH_PASS_FILE.
// SSH invokes this only after key-based auth fails, preserving the
// try-keys-first flow. The script self-deletes after one use.
func writeRecordingAskpassScript() (string, error) {
	f, err := os.CreateTemp("", "rssh-askpass-*.sh")
	if err != nil {
		return "", err
	}
	// $1 is the prompt string SSH passes (e.g. "user@host's password: ")
	f.WriteString(`#!/bin/sh
# Prompt the user on /dev/tty (SSH_ASKPASS runs without a terminal).
printf '%s' "$1" >/dev/tty
stty -echo </dev/tty 2>/dev/null
IFS= read -r pass </dev/tty
stty echo </dev/tty 2>/dev/null
printf '\n' >/dev/tty
# Save password for the tunneled connection.
if [ -n "$RSSH_PASS_FILE" ]; then
  printf '%s' "$pass" > "$RSSH_PASS_FILE"
fi
printf '%s' "$pass"
rm -f "$0"
`)
	f.Close()
	os.Chmod(f.Name(), 0700)
	return f.Name(), nil
}

func execSSH(args []string) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found: %w", err)
	}

	fullArgs := append([]string{"ssh"}, args...)
	return syscall.Exec(sshPath, fullArgs, os.Environ())
}
