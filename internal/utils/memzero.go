// Package utils provides security-critical utility functions.
//
// SECURITY: This file contains memory safety primitives that are essential
// for preventing credential leakage through memory dumps or swap files.
package utils

import (
	"unsafe"
)

// MemZero securely overwrites a byte slice with zeros.
// This prevents sensitive data (API keys, tokens) from lingering in memory
// after use, which could be exposed through:
//   - Process memory dumps
//   - Swap file forensics
//   - Container escape attacks
//
// The implementation uses unsafe.Pointer to prevent the compiler from
// optimizing away the zeroing operation (dead store elimination).
//
//go:noinline
func MemZero(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use volatile-like semantics to prevent compiler optimization
	p := unsafe.Pointer(&b[0]) // #nosec G103 -- required to keep secret zeroing from being optimized away.
	for i := range b {
		*(*byte)(unsafe.Add(p, i)) = 0
	}
}

// SecureBytes is a byte slice wrapper that automatically zeroes its content
// when it goes out of scope (via explicit Close call).
// Usage pattern:
//
//	key := utils.NewSecureBytes(rawKey)
//	defer key.Close()
//	// ... use key.Bytes() ...
type SecureBytes struct {
	data []byte
}

// NewSecureBytes wraps a byte slice with automatic zeroing capability.
func NewSecureBytes(data []byte) *SecureBytes {
	return &SecureBytes{data: data}
}

// Bytes returns the underlying byte slice. The caller MUST NOT retain
// a reference after calling Close().
func (sb *SecureBytes) Bytes() []byte {
	return sb.data
}

// Len returns the length of the secure buffer.
func (sb *SecureBytes) Len() int {
	return len(sb.data)
}

// Close zeroes and releases the underlying data.
// After Close(), Bytes() returns nil.
func (sb *SecureBytes) Close() {
	if sb.data != nil {
		MemZero(sb.data)
		sb.data = nil
	}
}
