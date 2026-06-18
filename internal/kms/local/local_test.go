package local

import (
	"context"
	"encoding/hex"
	"os"
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
