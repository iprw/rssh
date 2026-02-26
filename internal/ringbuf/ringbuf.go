package ringbuf

import (
	"fmt"
	"io"
	"sync"
)

// Buffer is a fixed-size circular buffer that tracks absolute byte offsets.
// It supports replaying buffered data from any offset still in the buffer.
type Buffer struct {
	mu   sync.Mutex
	data []byte
	size int
	pos  int   // write position in the circular buffer
	off  int64 // absolute offset of next byte to be written
}

// New creates a ring buffer with the given capacity in bytes.
func New(size int) *Buffer {
	return &Buffer{
		data: make([]byte, size),
		size: size,
	}
}

// Write appends data to the buffer. If the data exceeds buffer capacity,
// older data is overwritten. Returns the number of bytes written.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(p)
	if n >= b.size {
		// Data larger than buffer — only keep the last b.size bytes
		copy(b.data, p[n-b.size:])
		b.pos = 0
		b.off += int64(n)
		return n, nil
	}

	// Write in up to two chunks (before and after wrap)
	first := b.size - b.pos
	if first >= n {
		copy(b.data[b.pos:], p)
	} else {
		copy(b.data[b.pos:], p[:first])
		copy(b.data, p[first:])
	}
	b.pos = (b.pos + n) % b.size
	b.off += int64(n)
	return n, nil
}

// Offset returns the absolute byte offset — the total number of bytes
// written to this buffer since creation.
func (b *Buffer) Offset() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.off
}

// Earliest returns the earliest offset still available in the buffer.
func (b *Buffer) Earliest() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.earliest()
}

func (b *Buffer) earliest() int64 {
	if b.off > int64(b.size) {
		return b.off - int64(b.size)
	}
	return 0
}

// ReplayFrom writes all buffered data from the given absolute offset to w.
// Returns an error if the requested offset has been overwritten.
func (b *Buffer) ReplayFrom(offset int64, w io.Writer) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if offset > b.off {
		return fmt.Errorf("offset %d is beyond current offset %d", offset, b.off)
	}

	earliest := b.earliest()
	if offset < earliest {
		return fmt.Errorf("offset %d is before earliest available %d (data overwritten)", offset, earliest)
	}

	if offset == b.off {
		return nil // nothing to replay
	}

	count := int(b.off - offset)
	// start is the ring-buffer index of the first byte to replay
	start := (b.pos - count + b.size*((count/b.size)+1)) % b.size

	if start+count <= b.size {
		_, err := w.Write(b.data[start : start+count])
		return err
	}

	// Wraps around — two writes
	first := b.size - start
	if _, err := w.Write(b.data[start:]); err != nil {
		return err
	}
	_, err := w.Write(b.data[:count-first])
	return err
}

// Acknowledge marks data up to the given offset as received by the peer.
// This is informational — the buffer still holds data until overwritten.
func (b *Buffer) Acknowledge(offset int64) {
	// In v1, this is a no-op. The ring buffer naturally overwrites old data.
	// A future optimization could use this to free buffer space earlier.
}
