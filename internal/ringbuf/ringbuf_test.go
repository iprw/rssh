package ringbuf

import (
	"bytes"
	"testing"
)

func TestNewBuffer(t *testing.T) {
	b := New(1024)
	if b.Offset() != 0 {
		t.Fatalf("expected offset 0, got %d", b.Offset())
	}
}

func TestWriteAndReplay(t *testing.T) {
	b := New(1024)

	data := []byte("hello world")
	n, err := b.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}

	if b.Offset() != int64(len(data)) {
		t.Fatalf("expected offset %d, got %d", len(data), b.Offset())
	}

	// Replay from offset 0 should return all data
	var buf bytes.Buffer
	err = b.ReplayFrom(0, &buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Fatalf("expected %q, got %q", data, buf.Bytes())
	}
}

func TestReplayPartial(t *testing.T) {
	b := New(1024)
	b.Write([]byte("hello world"))

	// Replay from offset 5 should return " world"
	var buf bytes.Buffer
	err := b.ReplayFrom(5, &buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if buf.String() != " world" {
		t.Fatalf("expected %q, got %q", " world", buf.String())
	}
}

func TestReplayAfterWrap(t *testing.T) {
	b := New(16) // small buffer to force wrap

	// Write 20 bytes into a 16-byte buffer
	b.Write([]byte("0123456789"))
	b.Write([]byte("abcdefghij"))

	// Total offset is 20, but buffer only holds last 16 bytes
	if b.Offset() != 20 {
		t.Fatalf("expected offset 20, got %d", b.Offset())
	}

	// Earliest available = 20 - 16 = 4
	// Replay from offset 3 should fail (too old)
	var buf bytes.Buffer
	err := b.ReplayFrom(3, &buf)
	if err == nil {
		t.Fatal("expected error for offset before buffer start")
	}

	// Replay from offset 4 (exactly the earliest available) should succeed
	buf.Reset()
	err = b.ReplayFrom(4, &buf)
	if err != nil {
		t.Fatalf("expected replay from earliest offset to succeed: %v", err)
	}
	// bytes 4..19 = "456789abcdefghij" (16 bytes)
	expected := "456789abcdefghij"
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestReplayOffsetTooOld(t *testing.T) {
	b := New(16)

	b.Write([]byte("0123456789abcdefghij")) // 20 bytes, buffer holds last 16

	// Earliest available offset is 20 - 16 = 4
	// Offset 3 is too old
	var buf bytes.Buffer
	err := b.ReplayFrom(3, &buf)
	if err == nil {
		t.Fatal("expected error for offset too old")
	}
}

func TestAcknowledge(t *testing.T) {
	b := New(1024)
	b.Write([]byte("hello"))
	b.Write([]byte(" world"))

	// Acknowledge first 5 bytes — those can be discarded
	b.Acknowledge(5)

	// Replay from 5 should still work
	var buf bytes.Buffer
	err := b.ReplayFrom(5, &buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if buf.String() != " world" {
		t.Fatalf("expected %q, got %q", " world", buf.String())
	}
}

func TestReplayFromCurrentOffset(t *testing.T) {
	b := New(1024)
	b.Write([]byte("hello"))

	// Replay from current offset should return empty
	var buf bytes.Buffer
	err := b.ReplayFrom(5, &buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty, got %q", buf.String())
	}
}
