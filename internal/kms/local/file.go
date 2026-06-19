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
// before calling Put, so files contain nonce+ciphertext+GCM tag only.
type FileBackend struct {
	dir string
}

// NewFileBackend creates a file-backed encrypted blob store.
func NewFileBackend(dir string) (*FileBackend, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("local KMS file backend requires a directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating local KMS key store directory: %w", err)
	}
	return &FileBackend{dir: dir}, nil
}

func (f *FileBackend) Get(keyID string) ([]byte, error) {
	path, err := f.keyPath(keyID)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
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
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(cp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing encrypted key blob: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting encrypted key file permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing encrypted key file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("committing encrypted key file: %w", err)
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
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), keyFileSuffix) {
			continue
		}
		encoded := strings.TrimSuffix(entry.Name(), keyFileSuffix)
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		keyIDs = append(keyIDs, string(raw))
	}
	return keyIDs, nil
}

func (f *FileBackend) keyPath(keyID string) (string, error) {
	if keyID == "" {
		return "", errors.New("key id must not be empty")
	}
	name := base64.RawURLEncoding.EncodeToString([]byte(keyID)) + keyFileSuffix
	return filepath.Join(f.dir, name), nil
}

var _ Backend = (*FileBackend)(nil)
