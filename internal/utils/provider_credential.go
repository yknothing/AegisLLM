package utils

import (
	"errors"
	"fmt"
)

// MaxProviderCredentialBytes is the maximum decrypted provider credential
// length accepted for an outbound Authorization header value.
const MaxProviderCredentialBytes = 16 << 10

// ValidateProviderCredentialHeaderValue accepts only non-empty, bounded
// printable ASCII credentials. The exact allowed byte range is 0x20 through
// 0x7e inclusive; CR, LF, NUL, all other control bytes, DEL, and non-ASCII
// bytes are rejected.
//
// SECURITY: This function does not copy, retain, log, or zero credential. The
// caller remains responsible for calling MemZero or SecureBytes.Close on every
// return path.
func ValidateProviderCredentialHeaderValue(credential []byte) error {
	if len(credential) == 0 {
		return errors.New("provider credential must not be empty")
	}
	if len(credential) > MaxProviderCredentialBytes {
		return fmt.Errorf("provider credential exceeds %d-byte limit", MaxProviderCredentialBytes)
	}
	for _, b := range credential {
		if b < 0x20 || b > 0x7e {
			return errors.New("provider credential must contain only printable ASCII bytes (0x20-0x7e)")
		}
	}
	return nil
}
