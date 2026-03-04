# rssh

SSH that survives network interruptions. `rssh` wraps `ssh` with a small HTTP relay on the remote host — when your connection drops, the session stays alive and resumes transparently.

No server setup, no configuration files, no tmux.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/iprw/rssh/main/install.sh | sh
```

Or with a custom path:

```sh
INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/iprw/rssh/main/install.sh | sh
```

Or from source (requires Go 1.26+):

```sh
go install github.com/iprw/rssh/cmd/rssh@latest
```

## Usage

```sh
rssh user@host                     # just like ssh
rssh -p 2222 -i ~/.ssh/key host    # all ssh flags work
rssh -L 8080:localhost:80 host     # port forwarding works
rssh user@host uptime              # remote commands work
```

### Options

```
--password <pw> SSH password (skips interactive prompt)
--h2            force HTTP/2 only
--h3            force HTTP/3 (QUIC) only
-t              route through Tor (socks5h://127.0.0.1:9050)
--proxy <addr>  SOCKS5 proxy address (e.g. 127.0.0.1:1080)
-v              verbose (rssh only)
-vv             verbose (rssh + ssh)
```

### Update

```sh
rssh update     # self-update to latest release
rssh version    # print current version
```

## How it works

```
laptop                        server
  |                             |
  |  1. ssh in, deploy relay    |
  |  ========================>  |
  |                          [relay]
  |  2. reconnect ssh through   |
  |     HTTP/2 or QUIC relay    |
  |  ========================>  |
  |                          [sshd]
```

1. `rssh` SSHs into the server, copies a small relay binary to `~/.rssh/`, and starts it
2. The relay opens an ephemeral HTTPS port. `rssh` reconnects SSH through it via `ProxyCommand`
3. If the network drops, the relay keeps running. `rssh` reconnects and replays missed bytes from ring buffers on both sides

The SSH session underneath is real — port forwarding, agent forwarding, `~.` escapes, ProxyJump, and `.ssh/config` all work normally. If the relay fails to start, `rssh` falls back to plain SSH.

## vs mosh

mosh replaces SSH's transport with a custom UDP protocol. This breaks port forwarding, scrollback, and tools that expect a real SSH connection.

`rssh` keeps real SSH underneath and just makes the transport resilient.

| | rssh | mosh |
|---|---|---|
| Port forwarding | yes | no |
| Scrollback | yes | no |
| Server install | automatic | manual |
| Firewall | HTTPS port | UDP 60000-61000 |
| Protocol | HTTP/2 + QUIC | SSP over UDP |

## Cross-architecture deploy

When the remote server has a different OS or architecture, `rssh` automatically downloads the correct binary from [GitHub Releases](https://github.com/iprw/rssh/releases) and caches it in `~/.rssh/bin/`. Supported targets:

- Linux: amd64, arm64, armv7, armv6, 386, mips, riscv64, ppc64le, s390x, loong64
- macOS: amd64, arm64
- Windows: amd64, arm64, 386
- Android: arm64, amd64
- FreeBSD, OpenBSD, NetBSD: amd64, arm64

You can also pre-place binaries at `~/.rssh/bin/rssh-linux-arm64` (etc.) for offline use.

## Project layout

```
cmd/rssh/        main binary, subcommand dispatch
internal/
  bootstrap/     CLI entrypoint, relay deploy, SSH exec
  proxy/         client-side HTTP streaming bridge
  relay/         server-side HTTP handler
  ringbuf/       ring buffer with offset tracking
  tlsutil/       self-signed TLS cert management
  token/         session token generation
```

## License

MIT
