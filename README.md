# rssh

`rssh` wraps `ssh` and tunnels your connection through a persistent HTTP/2 or QUIC relay on the remote host. When the network drops — Wi-Fi roaming, VPN reconnects, laptop sleep — the relay keeps your session alive and replays missed bytes on reconnect. No configuration, no server setup, no tmux.

## How it works

```
laptop                          server
  |                               |
  |  ssh + ProxyCommand           |
  |  =========================>   |
  |    HTTP/2 or HTTP/3 (QUIC)    |
  |    through relay process      |
  |  =========================>   |
  |                            [relay]
  |                               |
  |                            [sshd]
```

1. **Bootstrap**: `rssh` SSHs into the server, deploys a small relay binary, and starts it
2. **Tunnel**: The relay listens on an ephemeral HTTPS port. `rssh` reconnects SSH through it using `ProxyCommand`
3. **Reconnect**: If the network drops, the relay stays alive on the server. `rssh` reconnects transparently — the SSH session never dies

All data is buffered in ring buffers on both sides. On reconnect, missed bytes are replayed so nothing is lost.

## Features

- **Transparent reconnection** — survive Wi-Fi switches, VPN drops, laptop sleep
- **HTTP/2 + HTTP/3 (QUIC) racing** — both protocols are tried in parallel, fastest wins
- **Dedicated input connection** — keystrokes travel on a separate TCP stream, never blocked by heavy output
- **Auto-deploy** — relay binary is deployed and updated automatically via SSH
- **Auto-update** — relay is re-deployed when local binary changes (SHA256 hash check)
- **Idle timeout** — relay shuts down after 60s with no client (no zombies)
- **Tor support** — built-in SOCKS5 connector for routing through Tor
- **Password forwarding** — `--pass` flag with self-cleaning askpass scripts
- **Tiny binary** — ~3MB with UPX compression

## Why not mosh?

[mosh](https://mosh.org) solves a similar problem but takes a fundamentally different approach — it replaces SSH's transport entirely with its own UDP protocol and rebuilds your terminal state using SSP (State Synchronization Protocol). This means mosh can't forward ports, doesn't support scrollback, breaks tools that expect a real SSH connection, and needs its own server daemon installed and firewalled open.

`rssh` takes the opposite approach: it keeps real SSH underneath. Your connection is still a genuine `ssh` process with all its features — port forwarding, agent forwarding, `~.` escapes, ProxyJump, config files, everything. The relay just makes the underlying TCP transport resilient. If the relay fails to start, `rssh` falls back to plain SSH automatically.

| | rssh | mosh |
|---|---|---|
| Transport | Real SSH (wrapped) | Custom UDP protocol |
| Port forwarding | Yes (native SSH) | No |
| Scrollback | Yes | No |
| Server install | Auto-deployed | Manual (package manager) |
| Firewall | HTTPS (443-like) | UDP 60000-61000 |
| Protocol | HTTP/2 + QUIC | SSP over UDP |

## Install

```sh
go install github.com/iprw/rssh/cmd/rssh@latest
```

Or build from source:

```sh
git clone https://github.com/iprw/rssh
cd rssh
make build
```

Requires Go 1.25+. Optional: [UPX](https://upx.github.io/) for binary compression.

## Usage

```sh
# Basic usage (same flags as ssh)
rssh user@host

# With password
rssh --pass mypassword user@host

# Force HTTP/3 (QUIC) only
rssh --h3 user@host

# Force HTTP/2 only
rssh --h2 user@host

# Route through Tor
rssh --tor user@host

# Custom Tor SOCKS proxy
rssh --tor --tor-proxy 127.0.0.1:9150 user@host

# Verbose output (rssh debug info)
rssh -v user@host

# Extra verbose (rssh + ssh debug)
rssh -vv user@host

# All standard ssh flags work
rssh -p 2222 -i ~/.ssh/mykey -L 8080:localhost:80 user@host

# Run a remote command
rssh user@host uptime
```

## Subcommands

| Command | Purpose |
|---------|---------|
| `rssh [flags] host` | Connect via tunnelled SSH |
| `rssh proxy <url>` | ProxyCommand bridge (internal) |
| `rssh relay [flags]` | Relay server (internal) |
| `rssh connect --proxy <addr> <host> <port>` | SOCKS5 connector (internal) |

## Architecture

```
internal/
  bootstrap/   CLI entrypoint: arg parsing, relay deploy, SSH exec
  proxy/       Client-side HTTP streaming bridge (stdin/stdout <-> relay)
  relay/       Server-side HTTP handler (client <-> sshd)
  ringbuf/     Ring buffer with offset tracking for reconnect replay
  tlsutil/     Self-signed TLS cert generation and config
  token/       Session token generation and validation
cmd/rssh/      Main binary: subcommand dispatch
```

### Data flow

```
stdin -> [proxy] --HTTP POST body--> [relay] --> [sshd]
stdout <- [proxy] <-HTTP response--- [relay] <-- [sshd]
```

On reconnect, the client sends its `offset` (bytes already received). The relay replays everything after that offset from its ring buffer. The relay also reports its `inOffset` (bytes received from client) so the client can replay missed input.

### Protocol selection

| Mode | Transport | When |
|------|-----------|------|
| Auto (default) | H2 + H3 raced | Both tried in parallel, first success wins |
| `--h2` | HTTP/2 over TLS | TCP only, works through all firewalls |
| `--h3` | HTTP/3 over QUIC | UDP, lower latency, survives IP changes |

H3 uses a dedicated `/input` endpoint for all client input (QUIC streams don't support full-duplex POST bodies). H2 uses bidirectional POST streaming with an optional dedicated input connection.

## Cross-compilation

```sh
make release
```

Produces binaries in `dist/` for:
- `linux/amd64`, `linux/arm64`
- `darwin/amd64`, `darwin/arm64`

## Testing

```sh
make test
```

Includes unit tests for all packages and an integration test that exercises the full relay pipeline.

## License

MIT
