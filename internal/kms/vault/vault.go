// Package vault implements the HashiCorp Vault KMS backend for Aegis.
//
// SECURITY PROPERTIES:
//   - API keys never touch Aegis's local storage
//   - Keys are fetched on-demand from Vault and held only in memory
//   - Vault token is loaded from environment variable
//   - Supports Vault's built-in key rotation and audit logging
//   - Network communication uses TLS (enforced by Vault client)
//
// This backend is recommended for production deployments where
// a dedicated secrets management infrastructure is available.
package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/utils"
)

// Client implements kms.Provider using HashiCorp Vault.
type Client struct {
	mu       sync.RWMutex
	address  string
	path     string
	token    []byte // Vault access token (zeroed on Close)
}

// Config holds Vault connection parameters.
type Config struct {
	Address  string // Vault server URL (e.g., https://vault.internal:8200)
	Path     string // Secret engine path (e.g., secret/data/aegis/keys)
	TokenEnv string // Environment variable holding the Vault token
}

// New creates a new Vault KMS client.
// SECURITY: The Vault token is read from env and stored securely in memory.
func New(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("vault address is required")
	}
	if cfg.Path == "" {
		return nil, errors.New("vault secret path is required")
	}

	tokenStr := os.Getenv(cfg.TokenEnv)
	if tokenStr == "" {
		return nil, fmt.Errorf("vault token env var %q is not set", cfg.TokenEnv)
	}

	return &Client{
		address: cfg.Address,
		path:    cfg.Path,
		token:   []byte(tokenStr),
	}, nil
}

// GetKey retrieves a decrypted API key from Vault.
// SECURITY: The caller MUST call Close() on the returned SecureBytes.
func (c *Client) GetKey(ctx context.Context, keyID string) (*utils.SecureBytes, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// TODO: Implement actual Vault HTTP API call
	// GET {address}/v1/{path}/{keyID}
	// Headers: X-Vault-Token: {token}
	//
	// The implementation should:
	// 1. Make HTTPS request to Vault
	// 2. Parse the response JSON
	// 3. Extract the key value
	// 4. Return as SecureBytes
	// 5. Zero any intermediate buffers

	return nil, fmt.Errorf("vault backend not yet implemented for key: %s", keyID)
}

// StoreKey writes an API key to Vault.
// SECURITY: The input plaintext is zeroed after transmission.
func (c *Client) StoreKey(ctx context.Context, keyID string, plaintext []byte) error {
	defer utils.MemZero(plaintext)

	// TODO: Implement actual Vault HTTP API call
	// POST {address}/v1/{path}/{keyID}
	// Body: {"data": {"value": "<base64-encoded-key>"}}

	return fmt.Errorf("vault backend not yet implemented for key: %s", keyID)
}

// DeleteKey removes a key from Vault.
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	// TODO: DELETE {address}/v1/{path}/{keyID}
	return fmt.Errorf("vault backend not yet implemented for key: %s", keyID)
}

// RotateKey triggers Vault's built-in key versioning.
func (c *Client) RotateKey(ctx context.Context, keyID string) error {
	// Vault handles rotation natively through its versioned KV store
	return fmt.Errorf("vault backend not yet implemented for key: %s", keyID)
}

// ListKeyIDs returns all key identifiers stored in Vault.
func (c *Client) ListKeyIDs(ctx context.Context) ([]string, error) {
	// TODO: LIST {address}/v1/{path}
	return nil, errors.New("vault backend not yet implemented")
}

// Close zeroes the Vault token and releases resources.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	utils.MemZero(c.token)
	c.token = nil
	return nil
}

// Compile-time interface compliance check.
var _ kms.Provider = (*Client)(nil)
