package token

import "testing"

func TestGenerate(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(tok) != 64 { // 256 bits = 32 bytes = 64 hex chars
		t.Fatalf("expected 64 hex chars, got %d", len(tok))
	}
}

func TestUniqueness(t *testing.T) {
	t1, _ := Generate()
	t2, _ := Generate()
	if t1 == t2 {
		t.Fatal("tokens should be unique")
	}
}

func TestValidate(t *testing.T) {
	tok, _ := Generate()
	if !Validate(tok, tok) {
		t.Fatal("identical tokens should validate")
	}
	if Validate(tok, "wrong") {
		t.Fatal("different tokens should not validate")
	}
}
