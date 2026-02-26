package tlsutil

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := GenerateSelfSigned()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected certificate data")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert, err := GenerateSelfSigned()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if err := Save(cert, certPath, keyPath); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file missing: %v", err)
	}

	// Load and verify
	loaded, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Certificate) == 0 {
		t.Fatal("loaded cert has no data")
	}
}

func TestEnsure_GeneratesIfMissing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert, err := Ensure(certPath, keyPath)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected certificate")
	}

	// Call again — should load existing
	cert2, err := Ensure(certPath, keyPath)
	if err != nil {
		t.Fatalf("ensure again: %v", err)
	}
	if len(cert2.Certificate) == 0 {
		t.Fatal("expected certificate on reload")
	}
}

func TestTLSConfigServer(t *testing.T) {
	cert, _ := GenerateSelfSigned()
	cfg := ServerTLSConfig(cert)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(cfg.Certificates))
	}
}

func TestTLSConfigClient(t *testing.T) {
	cfg := ClientTLSConfig()
	if !cfg.InsecureSkipVerify {
		t.Fatal("client should skip verification")
	}
}

// Verify TLS handshake works between generated server and client configs
func TestTLSHandshake(t *testing.T) {
	cert, _ := GenerateSelfSigned()
	serverCfg := ServerTLSConfig(cert)
	clientCfg := ClientTLSConfig()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
		done <- nil
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	buf := make([]byte, 5)
	n, _ := conn.Read(buf)
	conn.Close()

	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(buf[:n]))
	}

	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
}
