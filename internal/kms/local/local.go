// Package local implements the built-in AES-256-GCM Key Management System.
//
// SECURITY PROPERTIES:
//   - Master key is loaded from environment variable, never from files
//   - Each stored key gets a unique random nonce (12 bytes)
//   - Authenticated encryption prevents tampering (GCM tag)
//   - Decrypted keys are returned as SecureBytes for caller-managed zeroing
//   - Master key byte slice is zeroed on Close
//
// THREAT MODEL:
//   - Protects against: database theft, config file exposure, log leakage
//   - Does NOT protect against: root access to running process memory
//   - For stronger guarantees, implement and wire the reserved Vault backend
package local

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/utils"
)

// Store implements kms.Provider using local AES-256-GCM encryption.
type Store struct {
	mu                     sync.RWMutex
	masterKey              []byte
	gcm                    cipher.AEAD
	backend                Backend
	minimumEnvelopeVersion int
	closed                 bool
}

// MigrationReport summarizes validated local-KMS storage formats.
type MigrationReport struct {
	Total    int
	Legacy   int
	V2       int
	Migrated int
}

var errStoreClosed = errors.New("local KMS store is closed")

var (
	envelopeMagic             = []byte("AEGISKEY")
	ErrInvalidEnvelope        = fmt.Errorf("%w: invalid encrypted envelope", kms.ErrDecryptFailed)
	ErrLegacyEnvelopeDisabled = fmt.Errorf("%w: legacy encrypted envelopes are disabled", kms.ErrDecryptFailed)
	ErrBackendNotFound        = errors.New("local KMS backend key not found")
)

const (
	envelopeVersion    = byte(2)
	envelopeHeaderSize = 10 // 8-byte magic, version, nonce length
	gcmNonceSize       = 12
)

var envelopeAADDomain = []byte("aegis/kms/local/envelope")

// Backend defines the storage interface for encrypted key blobs.
// Current runtime uses file and in-memory stores; other durable stores are
// reserved future backends.
type Backend interface {
	Get(keyID string) (ciphertext []byte, err error)
	Put(keyID string, ciphertext []byte) error
	Delete(keyID string) error
	List() ([]string, error)
}

// New creates a new local KMS store.
// The master key is read from the specified environment variable.
// SECURITY: The env var value is copied into a byte slice owned by Store. The
// process environment string is controlled by the OS/runtime and is not zeroed
// by this function.
func New(masterKeyEnv string, backend Backend) (*Store, error) {
	return NewWithMinimumEnvelopeVersion(masterKeyEnv, backend, 1)
}

// NewWithMinimumEnvelopeVersion creates a local KMS store with an explicit
// read-format floor. Version 1 permits legacy nil-AAD blobs for migration;
// version 2 rejects them after migration has completed.
func NewWithMinimumEnvelopeVersion(masterKeyEnv string, backend Backend, minimumEnvelopeVersion int) (*Store, error) {
	if backend == nil {
		return nil, errors.New("local KMS backend is required")
	}
	if minimumEnvelopeVersion != 1 && minimumEnvelopeVersion != 2 {
		return nil, errors.New("local KMS minimum envelope version must be 1 or 2")
	}

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
	if gcm.NonceSize() != gcmNonceSize {
		return nil, errors.New("local KMS requires a 12-byte GCM nonce")
	}

	return &Store{
		masterKey:              masterKey,
		gcm:                    gcm,
		backend:                backend,
		minimumEnvelopeVersion: minimumEnvelopeVersion,
	}, nil
}

// GetKey decrypts and returns an API key.
// SECURITY: The caller MUST call Close() on the returned SecureBytes.
func (s *Store) GetKey(ctx context.Context, keyID string) (*utils.SecureBytes, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errStoreClosed
	}
	if err := validateKeyID(keyID); err != nil {
		return nil, fmt.Errorf("%w: invalid key id: %v", kms.ErrKeyNotFound, err)
	}

	ciphertext, err := s.backend.Get(keyID)
	if err != nil {
		if errors.Is(err, ErrBackendNotFound) {
			return nil, fmt.Errorf("%w: %s", kms.ErrKeyNotFound, keyID)
		}
		return nil, fmt.Errorf("reading encrypted key blob: %w", err)
	}

	plaintext, err := s.openBlob(keyID, ciphertext)
	if err != nil {
		return nil, err
	}

	return utils.NewSecureBytes(plaintext), nil
}

// StoreKey encrypts and persists an API key.
// SECURITY: The input plaintext slice is zeroed after encryption.
func (s *Store) StoreKey(ctx context.Context, keyID string, plaintext []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer utils.MemZero(plaintext) // Zero input after use
	if s.closed {
		return errStoreClosed
	}
	if err := validateKeyID(keyID); err != nil {
		return err
	}

	ciphertext, err := s.sealV2Blob(keyID, plaintext)
	if err != nil {
		return err
	}

	if err := s.backend.Put(keyID, ciphertext); err != nil {
		return fmt.Errorf("storing encrypted key: %w", err)
	}

	return nil
}

// InspectFormats validates every encrypted blob and reports its format without
// modifying storage.
func (s *Store) InspectFormats(ctx context.Context) (MigrationReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return MigrationReport{}, errStoreClosed
	}
	return s.inspectFormatsLocked(ctx)
}

// MigrateLegacy validates all source blobs, copies the complete encrypted
// source set to an empty backup backend, and only then rewrites legacy blobs as
// v2. Individual source replacements inherit backend atomicity.
func (s *Store) MigrateLegacy(ctx context.Context, backup Backend) (MigrationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return MigrationReport{}, errStoreClosed
	}
	if backup == nil {
		return MigrationReport{}, errors.New("migration backup backend is required")
	}
	existing, err := backup.List()
	if err != nil {
		return MigrationReport{}, fmt.Errorf("listing migration backup: %w", err)
	}
	if len(existing) != 0 {
		return MigrationReport{}, errors.New("migration backup must be empty")
	}

	ids, err := s.backend.List()
	if err != nil {
		return MigrationReport{}, fmt.Errorf("listing source keys: %w", err)
	}
	sort.Strings(ids)
	report := MigrationReport{Total: len(ids)}
	type sourceBlob struct {
		keyID  string
		blob   []byte
		legacy bool
	}
	blobs := make([]sourceBlob, 0, len(ids))
	for _, keyID := range ids {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		blob, err := s.backend.Get(keyID)
		if err != nil {
			return report, fmt.Errorf("reading source key %q: %w", keyID, err)
		}
		plaintext, err := s.openBlob(keyID, blob)
		if err != nil {
			return report, fmt.Errorf("validating source key %q: %w", keyID, err)
		}
		utils.MemZero(plaintext)
		legacy := !bytes.HasPrefix(blob, envelopeMagic)
		if legacy {
			report.Legacy++
		} else {
			report.V2++
		}
		blobs = append(blobs, sourceBlob{keyID: keyID, blob: blob, legacy: legacy})
	}

	for _, item := range blobs {
		if err := backup.Put(item.keyID, item.blob); err != nil {
			return report, fmt.Errorf("backing up key %q: %w", item.keyID, err)
		}
	}
	for _, item := range blobs {
		if !item.legacy {
			continue
		}
		plaintext, err := s.openLegacyBlob(item.blob)
		if err != nil {
			return report, fmt.Errorf("decrypting legacy key %q: %w", item.keyID, err)
		}
		ciphertext, sealErr := s.sealV2Blob(item.keyID, plaintext)
		utils.MemZero(plaintext)
		if sealErr != nil {
			return report, fmt.Errorf("encrypting migrated key %q: %w", item.keyID, sealErr)
		}
		if err := s.backend.Put(item.keyID, ciphertext); err != nil {
			return report, fmt.Errorf("committing migrated key %q: %w", item.keyID, err)
		}
		report.Migrated++
	}
	return report, nil
}

func (s *Store) inspectFormatsLocked(ctx context.Context) (MigrationReport, error) {
	ids, err := s.backend.List()
	if err != nil {
		return MigrationReport{}, err
	}
	report := MigrationReport{Total: len(ids)}
	for _, keyID := range ids {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		blob, err := s.backend.Get(keyID)
		if err != nil {
			return report, err
		}
		plaintext, err := s.openBlob(keyID, blob)
		if err != nil {
			return report, err
		}
		utils.MemZero(plaintext)
		if bytes.HasPrefix(blob, envelopeMagic) {
			report.V2++
		} else {
			report.Legacy++
		}
	}
	return report, nil
}

func (s *Store) sealV2Blob(keyID string, plaintext []byte) ([]byte, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	header := make([]byte, envelopeHeaderSize)
	copy(header, envelopeMagic)
	header[len(envelopeMagic)] = envelopeVersion
	header[len(envelopeMagic)+1] = gcmNonceSize
	encrypted := s.gcm.Seal(nil, nonce, plaintext, envelopeAAD(header, keyID))
	result := make([]byte, 0, len(header)+len(nonce)+len(encrypted))
	result = append(result, header...)
	result = append(result, nonce...)
	result = append(result, encrypted...)
	return result, nil
}

func (s *Store) openBlob(keyID string, blob []byte) ([]byte, error) {
	if bytes.HasPrefix(blob, envelopeMagic) {
		return s.openV2Envelope(keyID, blob)
	}
	if s.minimumEnvelopeVersion >= 2 {
		return nil, ErrLegacyEnvelopeDisabled
	}
	return s.openLegacyBlob(blob)
}

func (s *Store) openV2Envelope(keyID string, blob []byte) ([]byte, error) {
	if len(blob) < envelopeHeaderSize {
		return nil, fmt.Errorf("%w: truncated header", ErrInvalidEnvelope)
	}
	header := blob[:envelopeHeaderSize]
	if header[len(envelopeMagic)] != envelopeVersion {
		return nil, fmt.Errorf("%w: unsupported version", ErrInvalidEnvelope)
	}
	nonceSize := int(header[len(envelopeMagic)+1])
	if nonceSize != s.gcm.NonceSize() {
		return nil, fmt.Errorf("%w: invalid nonce length", ErrInvalidEnvelope)
	}
	if len(blob) < envelopeHeaderSize+nonceSize+s.gcm.Overhead() {
		return nil, fmt.Errorf("%w: truncated ciphertext", ErrInvalidEnvelope)
	}
	nonce := blob[envelopeHeaderSize : envelopeHeaderSize+nonceSize]
	encrypted := blob[envelopeHeaderSize+nonceSize:]
	plaintext, err := s.gcm.Open(nil, nonce, encrypted, envelopeAAD(header, keyID))
	if err != nil {
		return nil, fmt.Errorf("%w: GCM authentication failed", kms.ErrDecryptFailed)
	}
	return plaintext, nil
}

func (s *Store) openLegacyBlob(blob []byte) ([]byte, error) {
	nonceSize := s.gcm.NonceSize()
	if len(blob) < nonceSize+s.gcm.Overhead() {
		return nil, kms.ErrDecryptFailed
	}
	nonce := blob[:nonceSize]
	encrypted := blob[nonceSize:]
	plaintext, err := s.gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM authentication failed", kms.ErrDecryptFailed)
	}
	return plaintext, nil
}

func envelopeAAD(header []byte, keyID string) []byte {
	aad := make([]byte, 0, len(envelopeAADDomain)+len(header)+len(keyID))
	aad = append(aad, envelopeAADDomain...)
	aad = append(aad, header...)
	aad = append(aad, keyID...)
	return aad
}

func validateKeyID(keyID string) error {
	if keyID == "" {
		return errors.New("key id must not be empty")
	}
	if len(keyID) > kms.MaxKeyIDBytes {
		return fmt.Errorf("key id exceeds %d-byte limit", kms.MaxKeyIDBytes)
	}
	return nil
}

// DeleteKey removes a key from the store.
func (s *Store) DeleteKey(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStoreClosed
	}
	if err := validateKeyID(keyID); err != nil {
		return err
	}
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errStoreClosed
	}
	return s.backend.List()
}

// Close zeroes Store's master key byte slice and releases resources. The Go
// AES/GCM implementation may keep internal key schedule material that this
// package cannot explicitly zero.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	utils.MemZero(s.masterKey)
	s.masterKey = nil
	s.gcm = nil
	s.closed = true
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
		return nil, ErrBackendNotFound
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
