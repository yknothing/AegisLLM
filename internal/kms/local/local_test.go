package local

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreAndRetrieveKey(t *testing.T) {
	// Setup: Set a test master key in environment
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	masterKeyHex := hex.EncodeToString(masterKey)

	const envVar = "TEST_AEGIS_MASTER_KEY"
	os.Setenv(envVar, masterKeyHex)
	defer os.Unsetenv(envVar)

	// Create store with in-memory backend
	store, err := New(envVar, NewMemoryBackend())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Store a key
	testKey := []byte("sk-test-api-key-12345")
	err = store.StoreKey(ctx, "test-key-1", testKey)
	if err != nil {
		t.Fatalf("failed to store key: %v", err)
	}

	// Verify the original was zeroed
	for _, b := range testKey {
		if b != 0 {
			t.Fatal("original plaintext was not zeroed after StoreKey")
		}
	}

	// Retrieve the key
	secureKey, err := store.GetKey(ctx, "test-key-1")
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	defer secureKey.Close()

	if string(secureKey.Bytes()) != "sk-test-api-key-12345" {
		t.Fatalf("retrieved key mismatch: got %q", string(secureKey.Bytes()))
	}
}

func TestGetKeyNotFound(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_MASTER_KEY_2"
	os.Setenv(envVar, masterKeyHex)
	defer os.Unsetenv(envVar)

	store, err := New(envVar, NewMemoryBackend())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	_, err = store.GetKey(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent key, got nil")
	}
}

func TestSecureBytesClose(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_MASTER_KEY_3"
	os.Setenv(envVar, masterKeyHex)
	defer os.Unsetenv(envVar)

	store, err := New(envVar, NewMemoryBackend())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	original := []byte("secret-api-key")
	_ = store.StoreKey(ctx, "close-test", append([]byte{}, original...))

	secureKey, _ := store.GetKey(ctx, "close-test")

	// Close should zero the bytes
	secureKey.Close()

	if secureKey.Bytes() != nil {
		t.Fatal("SecureBytes.Bytes() should return nil after Close()")
	}
}

func TestInvalidMasterKey(t *testing.T) {
	const envVar = "TEST_AEGIS_INVALID_KEY"

	// Test: empty env var
	os.Setenv(envVar, "")
	_, err := New(envVar, NewMemoryBackend())
	if err == nil {
		t.Fatal("expected error for empty master key")
	}

	// Test: non-hex value
	os.Setenv(envVar, "not-hex-value")
	_, err = New(envVar, NewMemoryBackend())
	if err == nil {
		t.Fatal("expected error for non-hex master key")
	}

	// Test: wrong length
	os.Setenv(envVar, hex.EncodeToString(make([]byte, 16))) // 128-bit, not 256-bit
	_, err = New(envVar, NewMemoryBackend())
	if err == nil {
		t.Fatal("expected error for wrong-length master key")
	}

	os.Unsetenv(envVar)
}

func TestFileBackendPersistsEncryptedKeys(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_FILE_BACKEND_KEY"
	t.Setenv(envVar, masterKeyHex)

	dir := t.TempDir()
	backend, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend returned error: %v", err)
	}

	store, err := New(envVar, backend)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	ctx := context.Background()

	plaintext := []byte("sk-file-backed-key")
	if err := store.StoreKey(ctx, "openai-key-1", plaintext); err != nil {
		t.Fatalf("StoreKey returned error: %v", err)
	}
	_ = store.Close()

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("file count = %d, want 1", len(files))
	}
	info, err := files[0].Info()
	if err != nil {
		t.Fatalf("Info returned error: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file mode = %v, want 0600", info.Mode().Perm())
	}

	raw, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(raw) == "sk-file-backed-key" {
		t.Fatal("file backend stored plaintext")
	}

	reopened, err := New(envVar, backend)
	if err != nil {
		t.Fatalf("reopen New returned error: %v", err)
	}
	defer reopened.Close()

	key, err := reopened.GetKey(ctx, "openai-key-1")
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	defer key.Close()
	if string(key.Bytes()) != "sk-file-backed-key" {
		t.Fatalf("key = %q, want persisted plaintext", string(key.Bytes()))
	}

	keyIDs, err := reopened.ListKeyIDs(ctx)
	if err != nil {
		t.Fatalf("ListKeyIDs returned error: %v", err)
	}
	if len(keyIDs) != 1 || keyIDs[0] != "openai-key-1" {
		t.Fatalf("key IDs = %#v, want openai-key-1", keyIDs)
	}

	if err := reopened.DeleteKey(ctx, "openai-key-1"); err != nil {
		t.Fatalf("DeleteKey returned error: %v", err)
	}
	if _, err := reopened.GetKey(ctx, "openai-key-1"); err == nil {
		t.Fatal("GetKey succeeded after DeleteKey")
	}
}
