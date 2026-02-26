package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Generate creates a cryptographically random 256-bit session token
// encoded as a 64-character hex string.
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Validate compares two tokens in constant time.
func Validate(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
