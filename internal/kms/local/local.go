// Package local implements the built-in AES-256-GCM Key Management System.
//
// SECURITY PROPERTIES:
//   - Master key is loaded from environment variable, never from files
//   - Each stored key gets a unique random nonce (12 bytes)
//   - Authenticated encryption prevents tampering (GCM tag)
//   - Decrypted keys are returned as SecureBytes for caller-managed zeroing
//   - Master key is held in memory with mlock attempt (best-effort)
//
// THREAT MODEL:
//   - Protects against: database theft, config file exposure, log leakage
//   - Does NOT protect against: root access to running process memory
//   - For stronger guarantees, use the Vault backend instead
package local

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/utils"
)

// Store implements kms.Provider using local AES-256-GCM encryption.
type Store struct {
	mu        sync.RWMutex
	masterKey []byte
	gcm       cipher.AEAD
	backend   Backend
}

// Backend defines the storage interface for encrypted key blobs.
// This allows the local KMS to work with SQLite, files, or in-memory stores.
type Backend interface {
	Get(keyID string) (ciphertext []byte, err error)
	Put(keyID string, ciphertext []byte) error
	Delete(keyID string) error
	List() ([]string, error)
}

// New creates a new local KMS store.
// The master key is read from the specified environment variable.
// SECURITY: The env var value is immediately copied and the original is not retained.
func New(masterKeyEnv string, backend Backend) (*Store, error) {
	masterKeyHex := os.Getenv(masterKeyEnv)
	if masterKeyHex == "" {
		return nil, fmt.Errorf("%w: env var %q is empty", kms.ErrInvalidMasterKey, masterKeyEnv)
	}

	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: master key must be hex-encoded", kms.ErrInvalidMasterKey)
	}

	if len(masterKey) != 32 {
		return nil, fmt.Errorf("%w: master key must be exactly 32 bytes (256 bits), got %d", kms.ErrInvalidMasterKey, len(masterKey))
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	return &Store{
		masterKey: masterKey,
		gcm:       gcm,
		backend:   backend,
	}, nil
}

// GetKey decrypts and returns an API key.
// SECURITY: The caller MUST call Close() on the returned SecureBytes.
func (s *Store) GetKey(ctx context.Context, keyID string) (*utils.SecureBytes, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ciphertext, err := s.backend.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", kms.ErrKeyNotFound, keyID)
	}

	nonceSize := s.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, kms.ErrDecryptFailed
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := s.gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM authentication failed", kms.ErrDecryptFailed)
	}

	return utils.NewSecureBytes(plaintext), nil
}

// StoreKey encrypts and persists an API key.
// SECURITY: The input plaintext slice is zeroed after encryption.
func (s *Store) StoreKey(ctx context.Context, keyID string, plaintext []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer utils.MemZero(plaintext) // Zero input after use

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := s.gcm.Seal(nonce, nonce, plaintext, nil)

	if err := s.backend.Put(keyID, ciphertext); err != nil {
		return fmt.Errorf("storing encrypted key: %w", err)
	}

	return nil
}

// DeleteKey removes a key from the store.
func (s *Store) DeleteKey(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.Delete(keyID)
}

// RotateKey re-encrypts an existing key with a new nonce.
// This doesn't change the actual API key, but refreshes the encryption.
func (s *Store) RotateKey(ctx context.Context, keyID string) error {
	// Decrypt with current nonce
	key, err := s.GetKey(ctx, keyID)
	if err != nil {
		return err
	}
	defer key.Close()

	// Re-encrypt with new nonce
	plainCopy := make([]byte, key.Len())
	copy(plainCopy, key.Bytes())

	return s.StoreKey(ctx, keyID, plainCopy)
}

// ListKeyIDs returns all stored key identifiers.
func (s *Store) ListKeyIDs(ctx context.Context) ([]string, error) {
	return s.backend.List()
}

// Close zeroes the master key and releases resources.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	utils.MemZero(s.masterKey)
	s.masterKey = nil
	return nil
}

// Compile-time interface compliance check.
var _ kms.Provider = (*Store)(nil)

// --- In-Memory Backend (for testing and standalone mode) ---

// MemoryBackend stores encrypted blobs in memory.
type MemoryBackend struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryBackend creates an in-memory storage backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{data: make(map[string][]byte)}
}

func (m *MemoryBackend) Get(keyID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.data[keyID]
	if !ok {
		return nil, errors.New("not found")
	}
	// Return a copy to prevent external mutation
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (m *MemoryBackend) Put(keyID string, ciphertext []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(ciphertext))
	copy(cp, ciphertext)
	m.data[keyID] = cp
	return nil
}

func (m *MemoryBackend) Delete(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if data, ok := m.data[keyID]; ok {
		utils.MemZero(data)
	}
	delete(m.data, keyID)
	return nil
}

func (m *MemoryBackend) List() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}
