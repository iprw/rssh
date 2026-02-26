package relay

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/iprw/rssh/internal/ringbuf"
	"github.com/iprw/rssh/internal/token"
)

// Config holds relay configuration.
type Config struct {
	Token       string
	SSHDAddr    string
	BufSize     int
	NoTLS       bool
	IdleTimeout time.Duration // shut down if no client connected for this long (default 60s)
}

// Relay manages a single SSH session bridged over HTTP streaming.
type Relay struct {
	cfg          Config
	mu           sync.Mutex
	sshdConn     net.Conn
	outBuf       *ringbuf.Buffer // data sent toward client (sshd -> client)
	inBuf        *ringbuf.Buffer // data sent toward sshd (client -> sshd)
	cancelClient context.CancelFunc

	// Dedicated input connection (separate TCP to avoid head-of-line blocking).
	cancelInput context.CancelFunc

	// notify is closed and recreated whenever new data arrives in outBuf.
	notifyMu sync.Mutex
	notify   chan struct{}

	// done is closed when the sshd connection drops (session over).
	done chan struct{}

	// Idle timeout: relay exits if no client is connected for too long.
	idle            chan struct{} // closed when idle timeout fires
	clientConnected chan struct{} // signaled when a client connects
	clientDone      chan struct{} // signaled when a client disconnects
}

// New creates a new Relay with the given config.
func New(cfg Config) *Relay {
	if cfg.BufSize <= 0 {
		cfg.BufSize = 4 * 1024 * 1024 // 4MB default
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	r := &Relay{
		cfg:             cfg,
		outBuf:          ringbuf.New(cfg.BufSize),
		inBuf:           ringbuf.New(cfg.BufSize),
		notify:          make(chan struct{}),
		done:            make(chan struct{}),
		idle:            make(chan struct{}),
		clientConnected: make(chan struct{}, 1),
		clientDone:      make(chan struct{}, 1),
	}
	go r.watchIdle()
	return r
}

// Idle returns a channel that is closed when the relay has been idle
// (no connected client) for longer than IdleTimeout.
func (r *Relay) Idle() <-chan struct{} { return r.idle }

// watchIdle monitors client connections and fires the idle timeout
// when no client is connected for too long. Handles both startup
// (no client ever connects) and post-disconnect (client left).
func (r *Relay) watchIdle() {
	timer := time.NewTimer(r.cfg.IdleTimeout)
	defer timer.Stop()

	for {
		select {
		case <-r.clientConnected:
			// Client connected — stop the idle timer.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-r.clientDone:
			// Client disconnected — restart the idle timer.
			timer.Reset(r.cfg.IdleTimeout)
		case <-timer.C:
			log.Printf("[relay] idle timeout (%v with no client), shutting down", r.cfg.IdleTimeout)
			close(r.idle)
			return
		case <-r.done:
			return
		}
	}
}

// Done returns a channel that is closed when the sshd connection drops
// (i.e. the SSH session ended). Callers should shut down the listener.
func (r *Relay) Done() <-chan struct{} { return r.done }

// Handler returns the HTTP handler for the relay endpoints.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/connect", r.handleConnect)
	mux.HandleFunc("/input", r.handleInput)
	return mux
}

// httpStreamConn wraps an HTTP request/response pair as io.ReadWriteCloser.
// Read returns client input (from req.Body), Write sends relay output
// (via ResponseWriter + Flush).
type httpStreamConn struct {
	body    io.ReadCloser
	w       io.Writer
	flusher http.Flusher
}

func (c *httpStreamConn) Read(p []byte) (int, error) { return c.body.Read(p) }
func (c *httpStreamConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.flusher.Flush()
	}
	return n, err
}
func (c *httpStreamConn) Close() error { return c.body.Close() }

func (r *Relay) handleConnect(w http.ResponseWriter, req *http.Request) {
	// Validate token
	tok := req.URL.Query().Get("token")
	if !token.Validate(tok, r.cfg.Token) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Parse optional offset for reconnection
	var clientOffset int64
	if offStr := req.URL.Query().Get("offset"); offStr != "" {
		var err error
		clientOffset, err = strconv.ParseInt(offStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Disable response buffering for real-time streaming.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx, cancel := context.WithCancel(req.Context())

	// For GET requests (or empty POST body), input comes from the
	// separate /input endpoint. Use a reader that blocks until the
	// context is cancelled so the client→sshd goroutine doesn't exit.
	var body io.ReadCloser
	if req.Method == "POST" && req.Body != nil && req.ContentLength != 0 {
		body = req.Body
	} else {
		body = io.NopCloser(ctxReader{ctx})
	}

	nc := &httpStreamConn{
		body:    body,
		w:       w,
		flusher: flusher,
	}
	r.bridgeClient(ctx, cancel, nc, clientOffset)
}

// handleInput accepts a dedicated input-only HTTP connection.
// Input travels on a separate TCP connection so it never blocks behind
// heavy output traffic (head-of-line blocking fix).
func (r *Relay) handleInput(w http.ResponseWriter, req *http.Request) {
	tok := req.URL.Query().Get("token")
	if !token.Validate(tok, r.cfg.Token) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithCancel(req.Context())

	// Cancel previous input connection if any.
	r.mu.Lock()
	if r.cancelInput != nil {
		r.cancelInput()
	}
	r.cancelInput = cancel
	r.mu.Unlock()

	defer cancel()

	// Send 200 so the client unblocks and can start streaming the POST body.
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Read input from POST body and forward to sshd.
	buf := make([]byte, 32*1024)
	for {
		n, err := req.Body.Read(buf)
		if n > 0 {
			r.inBuf.Write(buf[:n])
			r.mu.Lock()
			if r.sshdConn != nil {
				r.sshdConn.Write(buf[:n])
			}
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// bridgeClient runs the relay bridge for a single client connection.
// It manages the sshd connection, sends the inBuf offset header, and
// bridges data bidirectionally. Works with any io.ReadWriteCloser
// (HTTP streaming, QUIC streams, etc).
func (r *Relay) bridgeClient(ctx context.Context, cancel context.CancelFunc, nc io.ReadWriteCloser, clientOffset int64) {
	defer cancel()

	// Signal client connected (stops idle timer).
	select {
	case r.clientConnected <- struct{}{}:
	default:
	}
	defer func() {
		// Signal client disconnected (restarts idle timer).
		select {
		case r.clientDone <- struct{}{}:
		default:
		}
	}()

	r.mu.Lock()

	// Disconnect previous client if any
	if r.cancelClient != nil {
		r.cancelClient()
	}
	r.cancelClient = cancel

	// First connection: establish sshd connection
	if r.sshdConn == nil {
		sshdConn, err := net.DialTimeout("tcp", r.cfg.SSHDAddr, 10*time.Second)
		if err != nil {
			r.mu.Unlock()
			log.Printf("[relay] sshd dial: %v", err)
			return
		}
		r.sshdConn = sshdConn

		// Start sshd -> outBuf reader (runs for lifetime of sshd connection)
		go r.readFromSSHD()
	}

	// Read inBuf offset while holding lock (old goroutine is cancelled,
	// so no concurrent writes to inBuf from the client→sshd direction).
	inOffset := r.inBuf.Offset()

	r.mu.Unlock()

	// Send input offset (8 bytes, big-endian) so the client knows exactly
	// how many client→sshd bytes the relay actually received. The client
	// uses this to replay any bytes lost in TCP buffers during disconnect.
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(inOffset))
	if _, err := nc.Write(hdr[:]); err != nil {
		log.Printf("[relay] write in-offset: %v", err)
		return
	}

	// Bridge: client -> sshd and outBuf -> client
	var wg sync.WaitGroup

	// Client -> sshd
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := nc.Read(buf)
			if n > 0 {
				r.inBuf.Write(buf[:n])
				r.mu.Lock()
				if r.sshdConn != nil {
					r.sshdConn.Write(buf[:n])
				}
				r.mu.Unlock()
			}
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// outBuf -> client: replays from clientOffset (handles both reconnect
	// replay and live data in one loop — no gap between replay and live).
	wg.Add(1)
	go func() {
		defer wg.Done()
		lastOffset := clientOffset
		for {
			// Check for data FIRST — catches anything already buffered
			// (reconnect replay, or data that arrived before goroutine started).
			currentOffset := r.outBuf.Offset()
			if currentOffset > lastOffset {
				var data []byte
				if err := r.outBuf.ReplayFrom(lastOffset, &bytesWriter{&data}); err != nil {
					log.Printf("[relay] replay: %v", err)
					cancel()
					return
				}
				if len(data) > 0 {
					if _, err := nc.Write(data); err != nil {
						cancel()
						return
					}
					lastOffset += int64(len(data))
				}
				continue // check again immediately — more data may have arrived
			}

			// No data pending — wait for notification or cancellation.
			r.notifyMu.Lock()
			ch := r.notify
			r.notifyMu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-ch:
			}
		}
	}()

	wg.Wait()
}

// readFromSSHD continuously reads from sshd and writes to outBuf.
// It notifies waiting goroutines via the notify channel whenever new data arrives.
func (r *Relay) readFromSSHD() {
	defer close(r.done) // signal that session is over

	buf := make([]byte, 32*1024)
	for {
		r.mu.Lock()
		conn := r.sshdConn
		r.mu.Unlock()
		if conn == nil {
			return
		}

		n, err := conn.Read(buf)
		if n > 0 {
			r.outBuf.Write(buf[:n])
			// Notify all waiters that new data is available
			r.notifyMu.Lock()
			close(r.notify)
			r.notify = make(chan struct{})
			r.notifyMu.Unlock()
		}
		if err != nil {
			log.Printf("[relay] sshd disconnected, shutting down")
			return
		}
	}
}

// bytesWriter is an io.Writer that appends to a byte slice.
type bytesWriter struct {
	buf *[]byte
}

func (w *bytesWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

// ListenAndServe starts the relay on the given address.
// Returns the actual address (useful when addr is ":0").
func ListenAndServe(ctx context.Context, addr string, handler http.Handler) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}

	actualAddr := ln.Addr().String()
	srv := &http.Server{Handler: handler}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[relay] serve error: %v", err)
		}
	}()

	return actualAddr, nil
}

// ListenAndServeTLS starts the relay with TLS on the given address.
// Returns the actual address (useful when addr is ":0").
func ListenAndServeTLS(ctx context.Context, addr string, handler http.Handler, srv *http.Server) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}

	actualAddr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[relay] serve tls error: %v", err)
		}
	}()

	return actualAddr, nil
}

// ListenAndServeQUIC starts an HTTP/3 (QUIC) server on the given UDP address,
// serving the same handler as the TCP listener. The addr should match the TCP
// port so clients can reach both protocols on the same host:port.
func ListenAndServeQUIC(ctx context.Context, addr string, handler http.Handler, tlsCfg *tls.Config) error {
	// Bind explicitly to IPv4 — "udp" may resolve to [::] which on some
	// Linux configs (net.ipv6.bindv6only=1) silently drops IPv4 packets.
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("resolve udp4: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp4: %w", err)
	}
	log.Printf("[relay] QUIC listening on udp4 %s", conn.LocalAddr())

	// Clone TLS config to avoid data race with http.Server.ServeTLS,
	// which mutates NextProtos on the shared config. QUIC requires "h3".
	h3TLS := tlsCfg.Clone()
	h3TLS.NextProtos = []string{"h3"}

	srv := &http3.Server{
		Handler:   handler,
		TLSConfig: h3TLS,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  120 * time.Second,
			KeepAlivePeriod: 15 * time.Second,
		},
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	go func() {
		if err := srv.Serve(conn); err != nil {
			log.Printf("[relay] h3 serve: %v", err)
		}
	}()

	return nil
}

// Port extracts just the port number from an addr like "127.0.0.1:PORT".
func Port(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

// ctxReader blocks on Read until the context is cancelled.
// Used for GET /connect requests where input arrives via /input.
type ctxReader struct{ ctx context.Context }

func (r ctxReader) Read(p []byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

var _ io.Writer = (*bytesWriter)(nil)
