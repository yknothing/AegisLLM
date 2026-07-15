package local

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const keyFileSuffix = ".key"

// FileBackend stores encrypted key blobs as files under a single directory.
//
// SECURITY: This backend never receives plaintext keys. The Store encrypts
// before calling Put, so files contain only a public versioned envelope,
// nonce, ciphertext, and GCM tag.
type FileBackend struct {
	dir string
}

// NewFileBackend creates a file-backed encrypted blob store.
func NewFileBackend(dir string) (*FileBackend, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("local KMS file backend requires a directory")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving local KMS key store directory: %w", err)
	}
	if err := os.MkdirAll(absDir, 0700); err != nil {
		return nil, fmt.Errorf("creating local KMS key store directory: %w", err)
	}
	info, err := os.Lstat(absDir)
	if err != nil {
		return nil, fmt.Errorf("checking local KMS key store directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("local KMS key store must be a non-symlink directory")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("local KMS key store directory permissions %o allow group/other writes", info.Mode().Perm())
	}
	return &FileBackend{dir: absDir}, nil
}

func (f *FileBackend) Get(keyID string) ([]byte, error) {
	path, err := f.keyPath(keyID)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrBackendNotFound
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("encrypted key blob must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("encrypted key blob permissions %o are not owner-only", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- keyPath restricts reads to encoded filenames under the configured key-store directory.
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrBackendNotFound
	}
	return raw, err
}

func (f *FileBackend) Put(keyID string, ciphertext []byte) error {
	path, err := f.keyPath(keyID)
	if err != nil {
		return err
	}

	cp := make([]byte, len(ciphertext))
	copy(cp, ciphertext)

	tmp, err := os.CreateTemp(f.dir, ".write-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temporary key file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(cp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing encrypted key blob: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting encrypted key file permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing encrypted key blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing encrypted key file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("committing encrypted key file: %w", err)
	}
	dir, err := os.Open(f.dir) // #nosec G304 -- f.dir is the validated configured key-store directory.
	if err != nil {
		return fmt.Errorf("opening local KMS directory for sync: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("syncing local KMS directory: %w", err)
	}
	return nil
}

func (f *FileBackend) Delete(keyID string) error {
	path, err := f.keyPath(keyID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (f *FileBackend) List() ([]string, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, err
	}

	keyIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), keyFileSuffix) {
			continue
		}
		if entry.IsDir() {
			return nil, errors.New("encrypted key filename refers to a directory")
		}
		encoded := strings.TrimSuffix(entry.Name(), keyFileSuffix)
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(raw) == 0 {
			return nil, errors.New("encrypted key filename is malformed")
		}
		if err := validateKeyID(string(raw)); err != nil {
			return nil, fmt.Errorf("encrypted key filename is invalid: %w", err)
		}
		keyIDs = append(keyIDs, string(raw))
	}
	return keyIDs, nil
}

func (f *FileBackend) keyPath(keyID string) (string, error) {
	if err := validateKeyID(keyID); err != nil {
		return "", err
	}
	name := base64.RawURLEncoding.EncodeToString([]byte(keyID)) + keyFileSuffix
	path := filepath.Join(f.dir, name)
	if filepath.Dir(path) != f.dir {
		return "", errors.New("key path escaped key store directory")
	}
	return path, nil
}

var _ Backend = (*FileBackend)(nil)
