package relay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)


// mockSSHD creates a TCP listener that echoes data back (simulates sshd)
func mockSSHD(t *testing.T) net.Listener {
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
				io.Copy(conn, conn) // echo
			}()
		}
	}()
	return ln
}

func TestRelayEcho(t *testing.T) {
	sshd := mockSSHD(t)
	defer sshd.Close()

	tok := "testtoken123"
	r := New(Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  4096,
	})

	// Test bridgeClient directly via net.Pipe (bypasses HTTP client issues).
	clientConn, relayConn := net.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go r.bridgeClient(ctx, cancel, relayConn, 0)

	// Read the input offset header (8 bytes)
	var hdr [8]byte
	if _, err := io.ReadFull(clientConn, hdr[:]); err != nil {
		t.Fatalf("read in-offset header: %v", err)
	}
	if binary.BigEndian.Uint64(hdr[:]) != 0 {
		t.Fatalf("expected offset 0, got %d", binary.BigEndian.Uint64(hdr[:]))
	}

	// Write data and read echo
	msg := []byte("hello sshd")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != "hello sshd" {
		t.Fatalf("expected %q, got %q", "hello sshd", string(buf))
	}
}

func TestRelayRejectsWrongToken(t *testing.T) {
	sshd := mockSSHD(t)
	defer sshd.Close()

	r := New(Config{
		Token:    "correct",
		SSHDAddr: sshd.Addr().String(),
		BufSize:  4096,
	})

	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/connect?token=wrong", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestRelayReconnect(t *testing.T) {
	sshd := mockSSHD(t)
	defer sshd.Close()

	tok := "reconnect-test"
	r := New(Config{
		Token:    tok,
		SSHDAddr: sshd.Addr().String(),
		BufSize:  4096,
	})

	// First connection
	clientConn1, relayConn1 := net.Pipe()

	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()

	go r.bridgeClient(ctx1, cancel1, relayConn1, 0)

	// Read offset header
	var hdr1 [8]byte
	if _, err := io.ReadFull(clientConn1, hdr1[:]); err != nil {
		t.Fatalf("read header 1: %v", err)
	}

	// Send data and read echo
	clientConn1.Write([]byte("first"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(clientConn1, buf); err != nil {
		t.Fatalf("read first: %v", err)
	}
	if string(buf) != "first" {
		t.Fatalf("expected %q, got %q", "first", string(buf))
	}

	// Close first connection (simulate network drop)
	clientConn1.Close()
	time.Sleep(100 * time.Millisecond)

	// Reconnect with offset=5 (we already received 5 bytes of output)
	clientConn2, relayConn2 := net.Pipe()
	defer clientConn2.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	go r.bridgeClient(ctx2, cancel2, relayConn2, 5)

	// Read offset header — relay tells us how many input bytes it received
	var hdr2 [8]byte
	if _, err := io.ReadFull(clientConn2, hdr2[:]); err != nil {
		t.Fatalf("read header 2: %v", err)
	}
	inOffset := binary.BigEndian.Uint64(hdr2[:])
	if inOffset != 5 {
		t.Fatalf("expected input offset 5, got %d", inOffset)
	}

	// Send more data on reconnected session
	clientConn2.Write([]byte("second"))
	buf2 := make([]byte, 6)
	n, err := io.ReadFull(clientConn2, buf2)
	if err != nil {
		t.Fatalf("read after reconnect: %v (got %d bytes: %q)", err, n, buf2[:n])
	}
	if string(buf2) != "second" {
		t.Fatalf("expected %q, got %q", "second", string(buf2))
	}
}

