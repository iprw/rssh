package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	socksProxy "golang.org/x/net/proxy"

	"github.com/iprw/rssh/internal/bootstrap"
	"github.com/iprw/rssh/internal/proxy"
	"github.com/iprw/rssh/internal/relay"
	"github.com/iprw/rssh/internal/tlsutil"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		printUsage()
		fmt.Fprintf(os.Stderr, "\n--- ssh usage ---\n\n")
		cmd := exec.Command("ssh")
		cmd.Stderr = os.Stderr
		cmd.Run()
		os.Exit(0)
	case "proxy":
		runProxy(os.Args[2:])
	case "relay":
		runRelay(os.Args[2:])
	case "connect":
		runConnect(os.Args[2:])
	default:
		runCLI(os.Args[1:])
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `rssh — resilient SSH with transparent reconnection

usage:
  rssh [flags] [user@]host [command]    connect via tunnelled SSH
  rssh proxy [flags] <url>              run as ProxyCommand (internal)
  rssh relay [flags]                    run as relay server (internal)
  rssh connect --proxy <addr> <h> <p>  SOCKS5 connector (internal)

flags:
  -v            verbose output (rssh only)
  -vv           verbose output (rssh + ssh)
  --pass <pw>   SSH password (avoids interactive prompt)
  --no-tls      disable TLS (use http instead of https)
  --h2          force HTTP/2 only (skip QUIC)
  --h3          force HTTP/3 (QUIC) only (skip HTTP/2)
  --tor         route through Tor (SOCKS5)
  --tor-proxy   Tor SOCKS5 address (default 127.0.0.1:9050)

By default, HTTP/3 (QUIC) and HTTP/2 are raced in parallel automatically.
All other flags (e.g. -p, -i, -L, -D) are passed through to ssh.
`)
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	noTLS := fs.Bool("no-tls", false, "disable TLS (use http:// instead of https://)")
	torProxy := fs.String("tor-proxy", "", "SOCKS5 proxy address for Tor routing (e.g. 127.0.0.1:9050)")
	verbose := fs.Bool("verbose", false, "enable verbose debug output")
	forceH2 := fs.Bool("h2", false, "force HTTP/2 only (skip H3/QUIC)")
	forceH3 := fs.Bool("h3", false, "force HTTP/3 (QUIC) only (skip H2)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: rssh proxy <url>\n")
		os.Exit(1)
	}
	wsURL := fs.Arg(0)

	// Build input URL by replacing /connect with /input in the URL.
	inputURL := strings.Replace(wsURL, "/connect", "/input", 1)

	cfg := proxy.Config{
		URL:      wsURL,
		InputURL: inputURL,
	}

	if !*noTLS {
		cfg.TLSConfig = tlsutil.ClientTLSConfig()
	}

	if *torProxy != "" {
		cfg.SOCKSAddr = *torProxy
	}

	cfg.Verbose = *verbose
	if *forceH3 {
		cfg.ForceProto = "h3"
	} else if *forceH2 {
		cfg.ForceProto = "h2"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := proxy.Run(ctx, cfg, os.Stdin, os.Stdout); err != nil {
		if ctx.Err() == nil {
			log.Fatalf("[rssh] proxy error: %v", err)
		}
	}
}

func runRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	tok := fs.String("token", "", "session token (required)")
	listen := fs.String("listen", ":0", "listen address")
	noTLS := fs.Bool("no-tls", false, "disable TLS")
	sshdAddr := fs.String("sshd", "127.0.0.1:23", "sshd address to connect to")
	idleTimeout := fs.Duration("idle-timeout", 60*time.Second, "shut down after this long with no client")
	fs.Parse(args)

	if *tok == "" {
		fmt.Fprintf(os.Stderr, "rssh relay: --token is required\n")
		os.Exit(1)
	}

	// Ignore SIGHUP (session hangup) and SIGPIPE (broken stdout/stderr pipe)
	// so the relay survives when the bootstrap SSH session exits.
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r := relay.New(relay.Config{
		Token:       *tok,
		SSHDAddr:    *sshdAddr,
		NoTLS:       *noTLS,
		IdleTimeout: *idleTimeout,
	})

	handler := r.Handler()

	var actualAddr string
	var err error

	if *noTLS {
		actualAddr, err = relay.ListenAndServe(ctx, *listen, handler)
		if err != nil {
			log.Fatalf("[rssh] relay listen: %v", err)
		}
	} else {
		// Ensure TLS cert exists in ~/.rssh/
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("[rssh] home dir: %v", err)
		}
		rsshDir := filepath.Join(homeDir, ".rssh")
		if err := os.MkdirAll(rsshDir, 0700); err != nil {
			log.Fatalf("[rssh] mkdir: %v", err)
		}
		certPath := filepath.Join(rsshDir, "cert.pem")
		keyPath := filepath.Join(rsshDir, "key.pem")

		cert, err := tlsutil.Ensure(certPath, keyPath)
		if err != nil {
			log.Fatalf("[rssh] TLS cert: %v", err)
		}

		tlsCfg := tlsutil.ServerTLSConfig(cert)
		srv := &http.Server{
			Handler:   handler,
			TLSConfig: tlsCfg,
		}

		actualAddr, err = relay.ListenAndServeTLS(ctx, *listen, handler, srv)
		if err != nil {
			log.Fatalf("[rssh] relay listen tls: %v", err)
		}

		// Also start HTTP/3 (QUIC) on the same port (UDP).
		// Non-fatal — relay still works over H2 if UDP is blocked.
		h3Port := relay.Port(actualAddr)
		if h3err := relay.ListenAndServeQUIC(ctx, ":"+h3Port, handler, tlsCfg); h3err != nil {
			log.Printf("[rssh] relay h3: %v (continuing with h2 only)", h3err)
		} else {
			log.Printf("[rssh] relay h3 listening on UDP :%s", h3Port)
		}
	}

	port := relay.Port(actualAddr)
	fmt.Printf("RSSH_PORT %s\n", port)

	// Wait for signal, sshd disconnect, or idle timeout.
	select {
	case <-ctx.Done():
	case <-r.Done():
		log.Printf("[rssh] session ended, relay shutting down")
		stop()
	case <-r.Idle():
		log.Printf("[rssh] idle timeout, relay shutting down")
		stop()
	}
}

// runConnect dials a target host:port through a SOCKS5 proxy and pipes
// stdin/stdout. Used as SSH ProxyCommand for Tor routing, replacing the
// external nc dependency.
func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	proxyAddr := fs.String("proxy", "127.0.0.1:9050", "SOCKS5 proxy address")
	fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "usage: rssh connect --proxy <addr> <host> <port>\n")
		os.Exit(1)
	}
	target := net.JoinHostPort(fs.Arg(0), fs.Arg(1))

	dialer, err := socksProxy.SOCKS5("tcp", *proxyAddr, nil, socksProxy.Direct)
	if err != nil {
		log.Fatalf("[rssh] socks5 dialer: %v", err)
	}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Fatalf("[rssh] connect %s via %s: %v", target, *proxyAddr, err)
	}
	defer conn.Close()

	done := make(chan struct{}, 1)
	go func() {
		io.Copy(conn, os.Stdin)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()
	<-done
}

func runCLI(args []string) {
	if err := bootstrap.Run(args); err != nil {
		fmt.Fprintf(os.Stderr, "[rssh] %v\n", err)
		os.Exit(1)
	}
}
