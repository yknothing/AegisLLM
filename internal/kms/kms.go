// Package kms defines the Key Management System interface for Aegis.
//
// SECURITY DESIGN:
//   - All provider API keys are stored encrypted at rest
//   - Keys are decrypted only in memory, only when needed
//   - After use, callers MUST call SecureBytes.Close() to zero memory
//   - The KMS interface abstracts over local encryption and external vaults
//
// This package is the single source of truth for credential access.
// No other package should ever directly read API keys from config or env.
package kms

import (
	"context"
	"errors"

	"github.com/yknothing/AegisLLM/internal/utils"
)

// Common errors returned by KMS implementations.
var (
	ErrKeyNotFound      = errors.New("kms: key not found")
	ErrDecryptFailed    = errors.New("kms: decryption failed")
	ErrVaultUnreachable = errors.New("kms: vault service unreachable")
	ErrInvalidMasterKey = errors.New("kms: invalid master key")
)

// Provider defines the interface for key management backends.
// Implementations include local AES-256-GCM and HashiCorp Vault.
type Provider interface {
	// GetKey retrieves a decrypted API key by its ID.
	// The returned SecureBytes MUST be closed by the caller after use.
	// SECURITY: Implementations must not cache decrypted keys.
	GetKey(ctx context.Context, keyID string) (*utils.SecureBytes, error)

	// StoreKey encrypts and stores an API key with the given ID.
	// The plaintext key is zeroed from the input after storage.
	StoreKey(ctx context.Context, keyID string, plaintext []byte) error

	// DeleteKey removes a key from the store.
	DeleteKey(ctx context.Context, keyID string) error

	// RotateKey generates a new encryption for an existing key.
	// This is used for periodic key rotation without changing the actual API key.
	RotateKey(ctx context.Context, keyID string) error

	// ListKeyIDs returns all stored key identifiers (never the keys themselves).
	ListKeyIDs(ctx context.Context) ([]string, error)

	// Close releases resources and zeroes any cached material.
	Close() error
}
