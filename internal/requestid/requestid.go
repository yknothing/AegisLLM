// Package requestid defines the safe request ID contract shared by the gateway
// server and proxy response metadata.
package requestid

import (
	cryptoRand "crypto/rand"
	"fmt"
	"strings"
	"time"
)

const (
	// Header is the gateway request ID response header.
	Header = "X-Request-ID"
	// UpstreamHeader carries provider request IDs without overwriting the
	// gateway request ID header.
	UpstreamHeader = "X-Upstream-Request-Id"
	// MaxLength is the longest accepted request ID in bytes.
	MaxLength = 128
)

// Safe reports whether id is safe to echo in response metadata.
func Safe(id string) bool {
	if id == "" || len(id) > MaxLength || strings.TrimSpace(id) != id {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return false
		}
	}
	return true
}

// Generate creates an unpredictable gateway request ID.
func Generate() string {
	b := make([]byte, 16)
	if _, err := cryptoRand.Read(b); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("req_%x", b)
}
