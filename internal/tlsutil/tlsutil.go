package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateSelfSigned creates a self-signed ECDSA P-256 certificate
// valid for 1 year. The cert is not tied to any specific hostname
// since the client skips verification (SSH provides real auth).
func GenerateSelfSigned() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"rssh-relay"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// Save writes a TLS certificate and private key to PEM files.
func Save(cert tls.Certificate, certPath, keyPath string) error {
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()

	for _, der := range cert.Certificate {
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return fmt.Errorf("encode cert: %w", err)
		}
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()

	privKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unexpected private key type: %T", cert.PrivateKey)
	}

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("encode key: %w", err)
	}

	return nil
}

// Load reads a TLS certificate and private key from PEM files.
func Load(certPath, keyPath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// Ensure loads an existing cert/key from disk, or generates and saves
// a new self-signed pair if the files don't exist.
func Ensure(certPath, keyPath string) (tls.Certificate, error) {
	if _, err := os.Stat(certPath); err == nil {
		return Load(certPath, keyPath)
	}

	cert, err := GenerateSelfSigned()
	if err != nil {
		return tls.Certificate{}, err
	}

	if err := Save(cert, certPath, keyPath); err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

// ServerTLSConfig returns a TLS config for the relay server using the given cert.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// ClientTLSConfig returns a TLS config for the proxy client.
// Verification is skipped because SSH provides the real authentication.
func ClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}
}
