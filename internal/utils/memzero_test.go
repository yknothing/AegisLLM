package utils

import (
	"testing"
)

func TestMemZero(t *testing.T) {
	data := []byte("sensitive-api-key-sk-12345")
	original := make([]byte, len(data))
	copy(original, data)

	MemZero(data)

	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte at index %d is %d, expected 0", i, b)
		}
	}
}

func TestMemZeroEmpty(t *testing.T) {
	// Should not panic on empty slice
	MemZero([]byte{})
	MemZero(nil)
}

func TestSecureBytes(t *testing.T) {
	raw := []byte("my-secret-value")
	sb := NewSecureBytes(raw)

	if sb.Len() != len(raw) {
		t.Fatalf("expected len %d, got %d", len(raw), sb.Len())
	}

	if string(sb.Bytes()) != "my-secret-value" {
		t.Fatal("Bytes() returned wrong content")
	}

	sb.Close()

	if sb.Bytes() != nil {
		t.Fatal("Bytes() should return nil after Close()")
	}

	// Verify the original backing array was zeroed
	for _, b := range raw {
		if b != 0 {
			t.Fatal("original backing array was not zeroed")
		}
	}
}

func TestSecureBytesDoubleClose(t *testing.T) {
	sb := NewSecureBytes([]byte("test"))
	sb.Close()
	sb.Close() // Should not panic
}
