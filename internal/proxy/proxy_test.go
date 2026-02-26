package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/iprw/rssh/internal/relay"
	"github.com/iprw/rssh/internal/tlsutil"
)

// echod creates a TCP echo server (simulates sshd)
func echod(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

func TestProxyBridge(t *testing.T) {
	// Start echo server (simulates sshd)
	sshd := echod(t)
	defer sshd.Close()

	// Generate self-signed TLS cert for HTTP/2
	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// Start relay with TLS (srv.ServeTLS auto-configures HTTP/2)
	tok := "proxytest"
	r := relay.New(relay.Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  4096,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := &http.Server{
		Handler:   r.Handler(),
		TLSConfig: tlsutil.ServerTLSConfig(cert),
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		srv.ServeTLS(ln, "", "")
	}()

	// Also start HTTP/3 (QUIC) on the same port so the H3 client connects.
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := relay.ListenAndServeQUIC(ctx, "127.0.0.1:"+port, r.Handler(), tlsutil.ServerTLSConfig(cert)); err != nil {
		t.Fatalf("quic listen: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	relayAddr := ln.Addr().String()
	connectURL := "https://" + relayAddr + "/connect?token=" + tok
	inputURL := "https://" + relayAddr + "/input?token=" + tok

	// Create proxy with fake stdin/stdout.
	// No HTTPClient override — buildHTTPClient uses TLSConfig with ForceAttemptHTTP2.
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	go func() {
		Run(ctx, Config{
			URL:              connectURL,
			InputURL:         inputURL,
			BufSize:          4096,
			TLSConfig:        tlsutil.ClientTLSConfig(),
			ReconnectTimeout: 3 * time.Second,
		}, stdinR, stdoutW)
	}()

	// Write to stdin, read echo from stdout
	stdinW.Write([]byte("hello"))

	buf := make([]byte, 5)
	n, err := io.ReadFull(stdoutR, buf)
	if err != nil {
		t.Fatalf("read: %v (got %d bytes)", err, n)
	}
	if string(buf) != "hello" {
		t.Fatalf("expected %q, got %q", "hello", string(buf))
	}
}

func TestContainsQuery(t *testing.T) {
	if !containsQuery("http://host:1234/connect?token=abc") {
		t.Fatal("expected true")
	}
	if containsQuery("http://host:1234/connect") {
		t.Fatal("expected false")
	}
}

func TestSOCKSHTTPClient(t *testing.T) {
	client := socksHTTPClient("127.0.0.1:9050", nil)
	if client == nil {
		t.Fatal("expected non-nil http.Client for valid SOCKS5 address")
	}
	if client.Transport == nil {
		t.Fatal("expected non-nil Transport on http.Client")
	}
}

func TestSOCKSHTTPClientInvalidAddr(t *testing.T) {
	client := socksHTTPClient("127.0.0.1:1", nil)
	if client == nil {
		t.Fatal("expected non-nil client even for unreachable proxy address")
	}
}
