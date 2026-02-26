package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/proxy"

	"github.com/iprw/rssh/internal/ringbuf"
)

// Config holds proxy configuration.
type Config struct {
	URL              string
	InputURL         string // separate /input endpoint for dedicated input connection
	BufSize          int
	TLSConfig        *tls.Config
	ReconnectTimeout time.Duration
	HTTPClient       *http.Client
	SOCKSAddr        string // e.g. "127.0.0.1:9050" for Tor
	Verbose          bool   // enable detailed debug output
	ForceProto       string // "h2" or "h3" to force a specific protocol; empty = auto-race
}

// logf prints a message to stderr. Always shown.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[rssh] "+format+"\r\n", args...)
}

// Run bridges stdin/stdout to the relay via HTTP streaming. It handles
// reconnection transparently — the caller never sees a disconnection.
func Run(ctx context.Context, cfg Config, stdin io.Reader, stdout io.Writer) error {
	if cfg.BufSize <= 0 {
		cfg.BufSize = 4 * 1024 * 1024
	}
	if cfg.ReconnectTimeout <= 0 {
		cfg.ReconnectTimeout = 30 * time.Second
	}

	// vlogf prints only when verbose is enabled.
	vlogf := func(format string, args ...any) {
		if cfg.Verbose {
			logf(format, args...)
		}
	}

	var h2Client, h3Client *http.Client
	switch cfg.ForceProto {
	case "h3":
		if cfg.TLSConfig == nil {
			return fmt.Errorf("--h3 requires TLS")
		}
		h3Client = buildH3Client(cfg.TLSConfig)
		// Quick UDP preflight: verify we can send a UDP packet at all.
		if host := extractHost(cfg.URL); host != "" {
			if err := probeUDP(host); err != nil {
				logf("WARNING: UDP preflight failed: %v", err)
				logf("H3 (QUIC) requires UDP connectivity — check firewall/VPN")
			} else {
				vlogf("UDP preflight OK: can reach %s", host)
			}
		}
	case "h2":
		h2Client = buildHTTPClient(cfg)
	default: // auto: build both, race
		h2Client = buildHTTPClient(cfg)
		if cfg.TLSConfig != nil && cfg.SOCKSAddr == "" && cfg.HTTPClient == nil {
			h3Client = buildH3Client(cfg.TLSConfig)
		}
	}

	vlogf("proxy config: url=%s socks=%s buf=%d reconnect=%v h3=%v h2=%v force=%s",
		cfg.URL, cfg.SOCKSAddr, cfg.BufSize, cfg.ReconnectTimeout, h3Client != nil, h2Client != nil, cfg.ForceProto)

	outOffset := int64(0) // bytes received from relay
	inBuf := ringbuf.New(cfg.BufSize)

	// activeNC is the current main connection (carries output, fallback input).
	// inputW is the dedicated input pipe (separate TCP, never blocked by output).
	var connMu sync.Mutex
	var activeNC net.Conn
	var inputW io.WriteCloser
	var inSent int64 // bytes from inBuf successfully sent to relay (atomic)

	// Single stdin reader — survives across reconnects. This avoids the
	// race where two goroutines read from stdin after a reconnect.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				inBuf.Write(buf[:n])
				connMu.Lock()
				iw := inputW   // prefer dedicated input connection
				nc := activeNC // fallback to main connection
				connMu.Unlock()
				if iw != nil {
					if _, werr := iw.Write(buf[:n]); werr == nil {
						atomic.AddInt64(&inSent, int64(n))
					} else {
						// Input conn broken — fall back to main
						connMu.Lock()
						inputW = nil
						connMu.Unlock()
						if nc != nil {
							if _, werr2 := nc.Write(buf[:n]); werr2 == nil {
								atomic.AddInt64(&inSent, int64(n))
							}
						}
					}
				} else if nc != nil {
					if _, werr := nc.Write(buf[:n]); werr == nil {
						atomic.AddInt64(&inSent, int64(n))
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	var deadline time.Time
	delay := 100 * time.Millisecond
	connNum := 0
	var h3OK bool
	activeClient := h2Client
	if activeClient == nil {
		activeClient = h3Client
	}

	for {
		connNum++
		dialStart := time.Now()
		logf("dialing relay (offset=%d)...", outOffset)

		var nc net.Conn
		var relayInOffset int64
		var proto string
		var err error

		if h3Client != nil && h2Client != nil && !h3OK {
			// Both clients available, first connect: race H3 and H2 in parallel.
			type dialResult struct {
				nc     net.Conn
				offset int64
				proto  string
				err    error
				client *http.Client
			}
			ch := make(chan dialResult, 2)
			go func() {
				n, o, p, e := dialHTTP(ctx, h3Client, cfg.URL, outOffset)
				ch <- dialResult{n, o, p, e, h3Client}
			}()
			go func() {
				n, o, p, e := dialHTTP(ctx, h2Client, cfg.URL, outOffset)
				ch <- dialResult{n, o, p, e, h2Client}
			}()

			// Take the first success; if both fail, report the second error.
			for i := 0; i < 2; i++ {
				r := <-ch
				if r.err == nil {
					nc, relayInOffset, proto, err = r.nc, r.offset, r.proto, nil
					activeClient = r.client
					if r.client == h3Client {
						h3OK = true
					}
					// Close the loser when it arrives.
					go func() {
						for j := i + 1; j < 2; j++ {
							if loser := <-ch; loser.err == nil {
								loser.nc.Close()
							}
						}
					}()
					break
				}
				vlogf("dial failed (%s): %v", r.proto, r.err)
				err = r.err
			}
		} else if h3Client != nil {
			// H3 only (forced via --h3, or H3 already proved itself).
			nc, relayInOffset, proto, err = dialHTTP(ctx, h3Client, cfg.URL, outOffset)
			if err == nil {
				activeClient = h3Client
				h3OK = true
			} else {
				vlogf("H3 dial failed: %v (will retry)", err)
			}
		} else {
			// H2 only (forced via --h2, or no TLS/SOCKS).
			nc, relayInOffset, proto, err = dialHTTP(ctx, h2Client, cfg.URL, outOffset)
			if err == nil {
				activeClient = h2Client
			}
		}

		if err == nil {
			logf("connected via %s (%v)", proto, time.Since(dialStart).Round(time.Millisecond))
		}

		if err != nil {
			// Dial failed — start or continue the reconnect window.
			if deadline.IsZero() {
				deadline = time.Now().Add(cfg.ReconnectTimeout)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("reconnect timeout after %v: %w", cfg.ReconnectTimeout, err)
			}

			logf("dial failed (%v), retrying in %v...", err, delay)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			if delay < 2*time.Second {
				delay *= 2
			}
			continue
		}

		// HTTP/3 (quic-go) doesn't reliably support full-duplex streaming
		// on a single POST: after the response arrives, the request-body
		// pipe may stop being consumed. Open the dedicated /input
		// connection FIRST so replay and stdin data flow through it.
		isH3 := strings.HasPrefix(proto, "HTTP/3")

		if cfg.InputURL != "" && isH3 {
			vlogf("opening dedicated input connection (H3, synchronous)...")
			iw, ierr := dialInputHTTP(ctx, activeClient, cfg.InputURL)
			if ierr != nil {
				vlogf("input connection failed (%v), using main connection for input", ierr)
			} else {
				vlogf("input connection established (separate stream)")
				connMu.Lock()
				inputW = iw
				connMu.Unlock()
			}
		}

		// Replay any client→sshd bytes the relay missed. Use the
		// dedicated input connection when available (critical for H3
		// where the main POST body pipe may block).
		connMu.Lock()
		replayW := io.Writer(nc)
		if inputW != nil {
			replayW = inputW
		}
		connMu.Unlock()

		buffered := inBuf.Offset()
		if buffered > relayInOffset {
			replayBytes := buffered - relayInOffset
			vlogf("replaying %d bytes (relay has %d, we buffered %d)", replayBytes, relayInOffset, buffered)
			if err := inBuf.ReplayFrom(relayInOffset, replayW); err == nil {
				atomic.StoreInt64(&inSent, buffered)
			}
		} else {
			vlogf("no replay needed (relay=%d, buffered=%d)", relayInOffset, buffered)
		}

		logf("tunnel established (#%d, %s)", connNum, proto)
		connMu.Lock()
		activeNC = nc
		connMu.Unlock()

		// For H2, open input connection asynchronously (bidirectional
		// POST works fine, so the main connection handles input until ready).
		if cfg.InputURL != "" && !isH3 {
			cl := activeClient
			go func() {
				vlogf("opening dedicated input connection...")
				iw, ierr := dialInputHTTP(ctx, cl, cfg.InputURL)
				if ierr != nil {
					vlogf("input connection failed (%v), using main connection for input", ierr)
					return
				}
				vlogf("input connection established (separate TCP)")
				connMu.Lock()
				inputW = iw
				connMu.Unlock()
			}()
		}

		// Close nc when context is cancelled so blocked reads unblock.
		go func() {
			<-ctx.Done()
			nc.Close()
		}()

		deadline = time.Time{}
		delay = 100 * time.Millisecond

		// relay → stdout (blocks until the connection drops)
		buf := make([]byte, 32*1024)
		for {
			n, readErr := nc.Read(buf)
			if n > 0 {
				outOffset += int64(n)
				if _, werr := stdout.Write(buf[:n]); werr != nil {
					connMu.Lock()
					activeNC = nil
					connMu.Unlock()
					nc.Close()
					return werr // stdout broken — unrecoverable
				}
			}
			if readErr != nil {
				break
			}
		}

		// Disconnected — clear both connections so stdin writes are buffered.
		connMu.Lock()
		activeNC = nil
		if inputW != nil {
			inputW.Close()
			inputW = nil
		}
		connMu.Unlock()
		nc.Close()

		if ctx.Err() != nil {
			return ctx.Err()
		}

		deadline = time.Now().Add(cfg.ReconnectTimeout)
		delay = 100 * time.Millisecond
		logf("connection lost, reconnecting...")
	}
}

// httpConn wraps HTTP response body (read/output) and a pipe writer
// (write/input) as a net.Conn for use in the reconnection loop.
type httpConn struct {
	r    io.ReadCloser  // resp.Body — relay output
	w    io.WriteCloser // pipe writer — client input
	resp *http.Response
}

func (c *httpConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *httpConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *httpConn) LocalAddr() net.Addr                { return httpAddr{} }
func (c *httpConn) RemoteAddr() net.Addr               { return httpAddr{} }
func (c *httpConn) SetDeadline(t time.Time) error      { return nil }
func (c *httpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *httpConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *httpConn) Close() error {
	c.w.Close()
	return c.r.Close()
}

type httpAddr struct{}

func (httpAddr) Network() string { return "tcp" }
func (httpAddr) String() string  { return "" }

// dialTimeout is the maximum time for a single dial attempt (TLS handshake +
// HTTP negotiation + reading the 8-byte offset header from the relay).
const dialTimeout = 15 * time.Second

// dialHTTP connects to the relay via HTTP POST with streaming body (input)
// and streaming response (output). Returns the connection, relay's input
// offset, the HTTP protocol version, and any error.
func dialHTTP(ctx context.Context, client *http.Client, rawURL string, offset int64) (net.Conn, int64, string, error) {
	url := rawURL
	sep := "&"
	if !containsQuery(url) {
		sep = "?"
	}
	url = fmt.Sprintf("%s%soffset=%d", url, sep, offset)

	pr, pw := io.Pipe()

	// Safety valve: if the dial takes too long (e.g. HTTP/1.1 streaming
	// POST deadlock, unresponsive server), close the pipe writer to
	// unblock client.Do(). We use a timer instead of context.WithTimeout
	// because the request must stay bound to the parent ctx — a dial-scoped
	// context would kill the live connection when the timeout expires.
	timer := time.AfterFunc(dialTimeout, func() {
		pw.CloseWithError(fmt.Errorf("dial timeout after %v", dialTimeout))
	})

	req, err := http.NewRequestWithContext(ctx, "POST", url, pr)
	if err != nil {
		timer.Stop()
		pw.Close()
		return nil, 0, "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		timer.Stop()
		pw.Close()
		return nil, 0, "", err
	}
	if resp.StatusCode != http.StatusOK {
		timer.Stop()
		pw.Close()
		resp.Body.Close()
		return nil, 0, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	proto := resp.Proto // "HTTP/1.1", "HTTP/2.0", etc.

	// Read the relay's input offset (first 8 bytes, big-endian).
	var hdr [8]byte
	if _, err := io.ReadFull(resp.Body, hdr[:]); err != nil {
		timer.Stop()
		pw.Close()
		resp.Body.Close()
		return nil, 0, "", fmt.Errorf("read in-offset: %w", err)
	}
	relayInOffset := int64(binary.BigEndian.Uint64(hdr[:]))

	timer.Stop() // Dial succeeded — cancel the safety valve.
	nc := &httpConn{r: resp.Body, w: pw, resp: resp}
	return nc, relayInOffset, proto, nil
}

// dialInputHTTP opens a dedicated input-only HTTP POST connection.
// Returns a WriteCloser for sending input data. The connection runs
// on a separate TCP socket so input never blocks behind output.
func dialInputHTTP(ctx context.Context, client *http.Client, rawURL string) (io.WriteCloser, error) {
	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, pr)
	if err != nil {
		pw.Close()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	// Start the POST in background. The server responds 200 OK immediately,
	// then reads from the streaming body for the lifetime of the connection.
	type result struct {
		err error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			ch <- result{err}
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			ch <- result{fmt.Errorf("input: HTTP %d", resp.StatusCode)}
			return
		}
		ch <- result{nil}
		// Keep reading response body (empty) until connection closes.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			pw.Close()
			return nil, r.err
		}
		return pw, nil
	case <-ctx.Done():
		pw.Close()
		return nil, ctx.Err()
	}
}

func containsQuery(url string) bool {
	for _, c := range url {
		if c == '?' {
			return true
		}
	}
	return false
}

// buildHTTPClient creates an HTTP client from the config.
func buildHTTPClient(cfg Config) *http.Client {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}
	if cfg.SOCKSAddr != "" {
		client := socksHTTPClient(cfg.SOCKSAddr, cfg.TLSConfig)
		if client != nil {
			return client
		}
	}
	if cfg.TLSConfig != nil {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     cfg.TLSConfig,
				ForceAttemptHTTP2:   true,
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		}
	}
	return http.DefaultClient
}

// buildH3Client creates an HTTP/3 (QUIC) client for the given TLS config.
func buildH3Client(tlsCfg *tls.Config) *http.Client {
	// Clone and set ALPN to "h3" — QUIC requires explicit protocol negotiation.
	h3TLS := tlsCfg.Clone()
	h3TLS.NextProtos = []string{"h3"}

	// Bind explicitly to IPv4 to avoid dual-stack routing issues.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		logf("H3: failed to create UDP socket: %v", err)
		return nil
	}
	logf("H3: UDP socket bound to %s", udpConn.LocalAddr())

	qTransport := &quic.Transport{Conn: udpConn}

	return &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: h3TLS,
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout: 5 * time.Second,
				MaxIdleTimeout:       120 * time.Second,
				KeepAlivePeriod:      15 * time.Second,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udpAddr, err := net.ResolveUDPAddr("udp4", addr)
				if err != nil {
					logf("H3: resolve %q failed: %v", addr, err)
					return nil, fmt.Errorf("resolve udp4 %s: %w", addr, err)
				}
				logf("H3: QUIC dialing %s from %s", udpAddr, udpConn.LocalAddr())
				conn, dialErr := qTransport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
				if dialErr != nil {
					logf("H3: QUIC dial failed: %v", dialErr)
					return nil, dialErr
				}
				logf("H3: QUIC connected to %s", udpAddr)
				return conn, nil
			},
		},
	}
}

// extractHost returns "host:port" from an https:// URL.
func extractHost(rawURL string) string {
	// Strip scheme
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip path
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// probeUDP sends a single UDP packet to the target to check basic connectivity.
// Returns nil if the packet was sent (doesn't guarantee delivery — UDP is fire-and-forget).
// Returns an error if the OS refuses to send (e.g. iptables DROP on OUTPUT).
func probeUDP(hostPort string) error {
	addr, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", hostPort, err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial udp %s: %w", hostPort, err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("send udp %s: %w", hostPort, err)
	}
	return nil
}

// socksHTTPClient builds an HTTP client that dials through a SOCKS5 proxy.
func socksHTTPClient(socksAddr string, tlsCfg *tls.Config) *http.Client {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:         contextDialer.DialContext,
			TLSClientConfig:     tlsCfg,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}
