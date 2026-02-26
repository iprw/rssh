//go:build integration

package main_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/iprw/rssh/internal/proxy"
	"github.com/iprw/rssh/internal/relay"
	"github.com/iprw/rssh/internal/tlsutil"
	"github.com/iprw/rssh/internal/token"
)

// echoServer starts a TCP echo server (simulates sshd) and returns its
// listener. Caller must close it.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
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

// TestIntegration_EchoOverHTTP exercises the full stack:
//  1. TCP echo server (simulates sshd)
//  2. Session token generation
//  3. Self-signed TLS cert generation
//  4. Relay (TLS HTTP server) pointing at the echo server
//  5. Proxy client connecting through the relay
//  6. Data sent via proxy stdin arrives back via proxy stdout (echoed)
func TestIntegration_EchoOverHTTP(t *testing.T) {
	// 1. Start echo server
	sshd := echoServer(t)
	defer sshd.Close()

	// 2. Generate session token
	tok, err := token.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// 3. Generate self-signed TLS certificate
	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	serverTLSCfg := tlsutil.ServerTLSConfig(cert)
	clientTLSCfg := tlsutil.ClientTLSConfig()

	// 4. Start relay with TLS
	r := relay.New(relay.Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  64 * 1024,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}

	relayAddr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := &http.Server{
		Handler:   r.Handler(),
		TLSConfig: serverTLSCfg,
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			t.Logf("relay serve tls: %v", err)
		}
	}()

	// Small delay to let TLS listener start accepting.
	time.Sleep(20 * time.Millisecond)

	// Build https:// URL
	connectURL := "https://" + relayAddr + "/connect?token=" + tok
	inputURL := "https://" + relayAddr + "/input?token=" + tok

	// 5. Connect via proxy (bridges stdio to HTTP streaming)
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	proxyCfg := proxy.Config{
		URL:              connectURL,
		InputURL:         inputURL,
		BufSize:          64 * 1024,
		TLSConfig:        clientTLSCfg,
		ReconnectTimeout: 5 * time.Second,
	}

	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- proxy.Run(ctx, proxyCfg, stdinR, stdoutW)
	}()

	// 6. Send data and verify echo
	const msg = "integration-test-payload"
	if _, err := stdinW.Write([]byte(msg)); err != nil {
		t.Fatalf("write to proxy stdin: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stdoutR, buf); err != nil {
		t.Fatalf("read from proxy stdout: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), msg)
	}

	// Cancel and wait for proxy to finish
	cancel()
	select {
	case <-proxyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not shut down in time")
	}
}

// TestIntegration_DirectHTTPEcho is a lower-level integration test that
// connects to the relay via HTTP POST directly (without going through the
// proxy) to verify the relay-sshd bridge works end-to-end with TLS.
func TestIntegration_DirectHTTPEcho(t *testing.T) {
	sshd := echoServer(t)
	defer sshd.Close()

	tok, err := token.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	r := relay.New(relay.Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  64 * 1024,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	time.Sleep(20 * time.Millisecond)

	connectURL := "https://" + ln.Addr().String() + "/connect?token=" + tok

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", connectURL, pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("http dial: %v", err)
	}
	defer resp.Body.Close()
	defer pw.Close()

	// Read the input offset header the relay sends first.
	var hdr [8]byte
	if _, err := io.ReadFull(resp.Body, hdr[:]); err != nil {
		t.Fatalf("read in-offset header: %v", err)
	}
	if binary.BigEndian.Uint64(hdr[:]) != 0 {
		t.Fatalf("expected offset 0, got %d", binary.BigEndian.Uint64(hdr[:]))
	}

	payload := []byte("direct-http-echo")
	if _, err := pw.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}
}

// TestIntegration_PlainHTTPEcho tests the relay without TLS (http://).
func TestIntegration_PlainHTTPEcho(t *testing.T) {
	sshd := echoServer(t)
	defer sshd.Close()

	tok, err := token.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	r := relay.New(relay.Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  64 * 1024,
		NoTLS:    true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayAddr, err := relay.ListenAndServe(ctx, "127.0.0.1:0", r.Handler())
	if err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}

	connectURL := "http://" + relayAddr + "/connect?token=" + tok
	inputURL := "http://" + relayAddr + "/input?token=" + tok

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	go func() {
		proxy.Run(ctx, proxy.Config{
			URL:              connectURL,
			InputURL:         inputURL,
			BufSize:          64 * 1024,
			ReconnectTimeout: 5 * time.Second,
		}, stdinR, stdoutW)
	}()

	const msg = "plain-http-integration"
	stdinW.Write([]byte(msg))

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stdoutR, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}

	// Verify token rejection works over plain HTTP too
	badCtx, badCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer badCancel()
	badReq, _ := http.NewRequestWithContext(badCtx, "POST", "http://"+relayAddr+"/connect?token=wrongtoken", nil)
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatalf("bad token request: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", badResp.StatusCode)
	}
}

// freeUDPAddr allocates a random UDP port on localhost and returns the address.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

// TestIntegration_H3DirectEcho verifies the HTTP/3 (QUIC) code path works
// end-to-end: echo server → relay (QUIC-only, no TCP) → H3 client.
// Asserts the connection actually negotiated HTTP/3.
func TestIntegration_H3DirectEcho(t *testing.T) {
	sshd := echoServer(t)
	defer sshd.Close()

	tok, err := token.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	serverTLSCfg := tlsutil.ServerTLSConfig(cert)

	r := relay.New(relay.Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  64 * 1024,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// QUIC-only: no TCP listener needed. Avoids the ServeTLS data race
	// on shared TLS config and proves the H3 path in isolation.
	relayAddr := freeUDPAddr(t)
	if err := relay.ListenAndServeQUIC(ctx, relayAddr, r.Handler(), serverTLSCfg); err != nil {
		t.Fatalf("start QUIC: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Build H3-only client.
	h3Client := &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
				NextProtos:         []string{"h3"},
			},
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout: 3 * time.Second,
				MaxIdleTimeout:       30 * time.Second,
			},
		},
	}

	connectURL := "https://" + relayAddr + "/connect?token=" + tok

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", connectURL, pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := h3Client.Do(req)
	if err != nil {
		t.Fatalf("H3 dial failed: %v", err)
	}
	defer resp.Body.Close()
	defer pw.Close()

	// Assert we actually negotiated HTTP/3.
	if resp.Proto != "HTTP/3.0" {
		t.Fatalf("expected protocol HTTP/3.0, got %s", resp.Proto)
	}

	// Read the 8-byte input offset header.
	var hdr [8]byte
	if _, err := io.ReadFull(resp.Body, hdr[:]); err != nil {
		t.Fatalf("read in-offset header: %v", err)
	}
	if binary.BigEndian.Uint64(hdr[:]) != 0 {
		t.Fatalf("expected offset 0, got %d", binary.BigEndian.Uint64(hdr[:]))
	}

	// Write payload and verify echo.
	payload := []byte("h3-quic-integration-echo")
	if _, err := pw.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}

	t.Logf("H3 echo passed: proto=%s", resp.Proto)
}

// TestIntegration_H3ProxyEcho exercises the full proxy stack over HTTP/3.
// Only a QUIC listener runs — no TCP — so the proxy's H2 dial fails and
// H3 must succeed. This proves the proxy's H3 racing logic works when
// H3 is the only available transport.
func TestIntegration_H3ProxyEcho(t *testing.T) {
	sshd := echoServer(t)
	defer sshd.Close()

	tok, err := token.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	cert, err := tlsutil.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	serverTLSCfg := tlsutil.ServerTLSConfig(cert)
	clientTLSCfg := tlsutil.ClientTLSConfig()

	r := relay.New(relay.Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  64 * 1024,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// QUIC-only: forces the proxy to use H3 (H2 dial will get connection refused).
	relayAddr := freeUDPAddr(t)
	if err := relay.ListenAndServeQUIC(ctx, relayAddr, r.Handler(), serverTLSCfg); err != nil {
		t.Fatalf("start QUIC: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	connectURL := "https://" + relayAddr + "/connect?token=" + tok
	inputURL := "https://" + relayAddr + "/input?token=" + tok

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	proxyCfg := proxy.Config{
		URL:              connectURL,
		InputURL:         inputURL,
		BufSize:          64 * 1024,
		TLSConfig:        clientTLSCfg,
		ReconnectTimeout: 5 * time.Second,
		Verbose:          true,
	}

	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- proxy.Run(ctx, proxyCfg, stdinR, stdoutW)
	}()

	// Send data and verify echo.
	const msg = "h3-proxy-full-stack-echo"
	if _, err := stdinW.Write([]byte(msg)); err != nil {
		t.Fatalf("write to proxy stdin: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stdoutR, buf); err != nil {
		t.Fatalf("read from proxy stdout: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), msg)
	}

	t.Logf("H3 proxy echo passed")

	cancel()
	select {
	case <-proxyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not shut down in time")
	}
}
