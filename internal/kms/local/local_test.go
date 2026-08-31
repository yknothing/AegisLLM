package local

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/kms"
)

func TestNewStoreFromMasterKeyZerosOwnedBytesOnFailure(t *testing.T) {
	tests := []struct {
		name      string
		masterKey []byte
		decodeErr error
	}{
		{
			name:      "partial hex decode",
			masterKey: bytes.Repeat([]byte{0xa5}, 16),
			decodeErr: errors.New("invalid hex byte"),
		},
		{
			name:      "wrong key length",
			masterKey: bytes.Repeat([]byte{0xa5}, 31),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owned := append([]byte(nil), tt.masterKey...)
			store, err := newStoreFromMasterKey(owned, tt.decodeErr, NewMemoryBackend(), 1)
			if err == nil {
				t.Fatal("newStoreFromMasterKey returned nil error")
			}
			if store != nil {
				t.Fatal("newStoreFromMasterKey returned a store on failure")
			}
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatalf("owned master key was not zeroed: %x", owned)
			}
		})
	}
}

func TestV2EnvelopeBindsCiphertextToKeyID(t *testing.T) {
	const envVar = "TEST_AEGIS_V2_AAD_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))
	backend := NewMemoryBackend()
	store, err := New(envVar, backend)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.StoreKey(context.Background(), "key-a", []byte("sk-secret-a")); err != nil {
		t.Fatalf("StoreKey returned error: %v", err)
	}
	blob, err := backend.Get("key-a")
	if err != nil {
		t.Fatalf("backend.Get returned error: %v", err)
	}
	if !bytes.HasPrefix(blob, envelopeMagic) {
		t.Fatalf("new blob prefix = %x, want v2 envelope magic", blob[:min(len(blob), len(envelopeMagic))])
	}

	if err := backend.Put("key-b", blob); err != nil {
		t.Fatalf("backend.Put returned error: %v", err)
	}
	if _, err := store.GetKey(context.Background(), "key-b"); !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, kms.ErrDecryptFailed) {
		t.Fatalf("GetKey swapped blob error = %v, want authenticated rejection", err)
	}
}

func TestV2EnvelopeCannotBeDowngradedByStrippingHeader(t *testing.T) {
	const envVar = "TEST_AEGIS_V2_DOWNGRADE_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))
	backend := NewMemoryBackend()
	store, err := New(envVar, backend)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.StoreKey(context.Background(), "key-a", []byte("sk-secret-a")); err != nil {
		t.Fatalf("StoreKey returned error: %v", err)
	}
	blob, _ := backend.Get("key-a")
	if err := backend.Put("key-a", append([]byte(nil), blob[envelopeHeaderSize:]...)); err != nil {
		t.Fatalf("backend.Put returned error: %v", err)
	}
	if _, err := store.GetKey(context.Background(), "key-a"); !errors.Is(err, kms.ErrDecryptFailed) {
		t.Fatalf("GetKey stripped envelope error = %v, want decrypt failure", err)
	}
}

func TestGetKeyReadsLegacyNilAADBlob(t *testing.T) {
	const envVar = "TEST_AEGIS_LEGACY_READ_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))
	backend := NewMemoryBackend()
	store, err := New(envVar, backend)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	nonce := make([]byte, store.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read returned error: %v", err)
	}
	legacy := store.gcm.Seal(nonce, nonce, []byte("sk-legacy-secret"), nil)
	if err := backend.Put("legacy-key", legacy); err != nil {
		t.Fatalf("backend.Put returned error: %v", err)
	}

	key, err := store.GetKey(context.Background(), "legacy-key")
	if err != nil {
		t.Fatalf("GetKey legacy blob returned error: %v", err)
	}
	defer key.Close()
	if string(key.Bytes()) != "sk-legacy-secret" {
		t.Fatalf("legacy key = %q, want original plaintext", key.Bytes())
	}
}

func TestStrictV2StoreRejectsRestoredLegacyBlob(t *testing.T) {
	const envVar = "TEST_AEGIS_STRICT_V2_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))
	backend := NewMemoryBackend()
	store, err := NewWithMinimumEnvelopeVersion(envVar, backend, 2)
	if err != nil {
		t.Fatalf("NewWithMinimumEnvelopeVersion returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	nonce := make([]byte, store.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read returned error: %v", err)
	}
	legacy := store.gcm.Seal(nonce, nonce, []byte("sk-restored-legacy"), nil)
	if err := backend.Put("restored-key", legacy); err != nil {
		t.Fatalf("backend.Put returned error: %v", err)
	}
	if _, err := store.GetKey(context.Background(), "restored-key"); !errors.Is(err, ErrLegacyEnvelopeDisabled) {
		t.Fatalf("GetKey strict legacy error = %v, want ErrLegacyEnvelopeDisabled", err)
	}
}

func TestGetKeyRejectsUnknownV2EnvelopeVersionWithoutLegacyFallback(t *testing.T) {
	const envVar = "TEST_AEGIS_UNKNOWN_ENVELOPE_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))
	backend := NewMemoryBackend()
	store, err := New(envVar, backend)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	blob := append([]byte(nil), envelopeMagic...)
	blob = append(blob, 99, byte(store.gcm.NonceSize()))
	blob = append(blob, make([]byte, store.gcm.NonceSize()+store.gcm.Overhead())...)
	if err := backend.Put("key-a", blob); err != nil {
		t.Fatalf("backend.Put returned error: %v", err)
	}
	if _, err := store.GetKey(context.Background(), "key-a"); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("GetKey unknown version error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestMigrateLegacyBacksUpAllBlobsBeforeRewriting(t *testing.T) {
	const envVar = "TEST_AEGIS_MIGRATION_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))
	source := NewMemoryBackend()
	store, err := New(envVar, source)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.StoreKey(context.Background(), "v2-key", []byte("sk-v2")); err != nil {
		t.Fatalf("StoreKey v2 returned error: %v", err)
	}
	nonce := make([]byte, store.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read returned error: %v", err)
	}
	legacyBlob := store.gcm.Seal(nonce, nonce, []byte("sk-legacy"), nil)
	if err := source.Put("legacy-key", legacyBlob); err != nil {
		t.Fatalf("source.Put legacy returned error: %v", err)
	}
	v2Before, _ := source.Get("v2-key")

	backup := NewMemoryBackend()
	report, err := store.MigrateLegacy(context.Background(), backup)
	if err != nil {
		t.Fatalf("MigrateLegacy returned error: %v", err)
	}
	if report.Total != 2 || report.Legacy != 1 || report.V2 != 1 || report.Migrated != 1 {
		t.Fatalf("migration report = %+v, want total=2 legacy=1 v2=1 migrated=1", report)
	}
	legacyBackup, _ := backup.Get("legacy-key")
	if !bytes.Equal(legacyBackup, legacyBlob) {
		t.Fatal("legacy backup does not match pre-migration blob")
	}
	v2Backup, _ := backup.Get("v2-key")
	if !bytes.Equal(v2Backup, v2Before) {
		t.Fatal("v2 backup does not match pre-migration blob")
	}
	migrated, _ := source.Get("legacy-key")
	if !bytes.HasPrefix(migrated, envelopeMagic) {
		t.Fatal("legacy source blob was not rewritten as v2")
	}

	secondBackup := NewMemoryBackend()
	second, err := store.MigrateLegacy(context.Background(), secondBackup)
	if err != nil {
		t.Fatalf("second MigrateLegacy returned error: %v", err)
	}
	if second.Legacy != 0 || second.Migrated != 0 || second.V2 != 2 {
		t.Fatalf("second migration report = %+v, want idempotent v2-only report", second)
	}
}

func TestMigrateLegacyRejectsNonEmptyBackupBeforeSourceMutation(t *testing.T) {
	const envVar = "TEST_AEGIS_MIGRATION_BACKUP_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))
	source := NewMemoryBackend()
	store, err := New(envVar, source)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	nonce := make([]byte, store.gcm.NonceSize())
	_, _ = rand.Read(nonce)
	legacyBlob := store.gcm.Seal(nonce, nonce, []byte("sk-legacy"), nil)
	_ = source.Put("legacy-key", legacyBlob)
	backup := NewMemoryBackend()
	_ = backup.Put("existing", []byte("occupied"))

	if _, err := store.MigrateLegacy(context.Background(), backup); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("MigrateLegacy backup error = %v, want empty-backup rejection", err)
	}
	after, _ := source.Get("legacy-key")
	if !bytes.Equal(after, legacyBlob) {
		t.Fatal("source changed after non-empty backup rejection")
	}
}

func TestMigrateLegacyDoesNotRetainSourceBlobBuffers(t *testing.T) {
	const envVar = "TEST_AEGIS_MIGRATION_STREAMING_KEY"
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 32)))

	seed := NewMemoryBackend()
	seedStore, err := New(envVar, seed)
	if err != nil {
		t.Fatalf("New seed store returned error: %v", err)
	}
	if err := seedStore.StoreKey(context.Background(), "key-a", []byte("secret-a")); err != nil {
		t.Fatalf("StoreKey key-a returned error: %v", err)
	}
	if err := seedStore.StoreKey(context.Background(), "key-b", []byte("secret-b")); err != nil {
		t.Fatalf("StoreKey key-b returned error: %v", err)
	}
	if err := seedStore.Close(); err != nil {
		t.Fatalf("Close seed store returned error: %v", err)
	}
	a, err := seed.Get("key-a")
	if err != nil {
		t.Fatalf("Get seed key-a returned error: %v", err)
	}
	b, err := seed.Get("key-b")
	if err != nil {
		t.Fatalf("Get seed key-b returned error: %v", err)
	}

	source := &reusingBlobBackend{data: map[string][]byte{
		"key-a": append([]byte(nil), a...),
		"key-b": append([]byte(nil), b...),
	}}
	store, err := New(envVar, source)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() { _ = store.Close() }()

	backup := NewMemoryBackend()
	if _, err := store.MigrateLegacy(context.Background(), backup); err != nil {
		t.Fatalf("MigrateLegacy returned error: %v", err)
	}
	backedUpA, _ := backup.Get("key-a")
	backedUpB, _ := backup.Get("key-b")
	if !bytes.Equal(backedUpA, a) {
		t.Fatal("key-a backup changed because migration retained a reusable source buffer")
	}
	if !bytes.Equal(backedUpB, b) {
		t.Fatal("key-b backup changed because migration retained a reusable source buffer")
	}
}

func TestStoreAndRetrieveKey(t *testing.T) {
	// Setup: Set a test master key in environment
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	masterKeyHex := hex.EncodeToString(masterKey)

	const envVar = "TEST_AEGIS_MASTER_KEY"
	t.Setenv(envVar, masterKeyHex)

	// Create store with in-memory backend
	store, err := New(envVar, NewMemoryBackend())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

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
	t.Setenv(envVar, masterKeyHex)

	store, err := New(envVar, NewMemoryBackend())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	_, err = store.GetKey(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent key, got nil")
	}
}

func TestSecureBytesClose(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_MASTER_KEY_3"
	t.Setenv(envVar, masterKeyHex)

	store, err := New(envVar, NewMemoryBackend())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

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

func TestStoreRejectsOperationsAfterClose(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_CLOSED_STORE_KEY"
	t.Setenv(envVar, masterKeyHex)

	store, err := New(envVar, NewMemoryBackend())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	if err := store.StoreKey(ctx, "closed-test", []byte("sk-before-close")); err != nil {
		t.Fatalf("StoreKey before Close returned error: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}

	if _, err := store.GetKey(ctx, "closed-test"); !errors.Is(err, errStoreClosed) {
		t.Fatalf("GetKey after Close error = %v, want errStoreClosed", err)
	}
	plaintext := []byte("sk-after-close")
	if err := store.StoreKey(ctx, "after-close", plaintext); !errors.Is(err, errStoreClosed) {
		t.Fatalf("StoreKey after Close error = %v, want errStoreClosed", err)
	}
	for _, b := range plaintext {
		if b != 0 {
			t.Fatal("StoreKey did not zero plaintext after closed-store failure")
		}
	}
	if err := store.DeleteKey(ctx, "closed-test"); !errors.Is(err, errStoreClosed) {
		t.Fatalf("DeleteKey after Close error = %v, want errStoreClosed", err)
	}
	if err := store.RotateKey(ctx, "closed-test"); !errors.Is(err, errStoreClosed) {
		t.Fatalf("RotateKey after Close error = %v, want errStoreClosed", err)
	}
	if _, err := store.ListKeyIDs(ctx); !errors.Is(err, errStoreClosed) {
		t.Fatalf("ListKeyIDs after Close error = %v, want errStoreClosed", err)
	}
}

func TestInvalidMasterKey(t *testing.T) {
	const envVar = "TEST_AEGIS_INVALID_KEY"

	// Test: empty env var
	t.Setenv(envVar, "")
	_, err := New(envVar, NewMemoryBackend())
	if err == nil {
		t.Fatal("expected error for empty master key")
	}

	// Test: non-hex value
	t.Setenv(envVar, "not-hex-value")
	_, err = New(envVar, NewMemoryBackend())
	if err == nil {
		t.Fatal("expected error for non-hex master key")
	}

	// Test: wrong length
	t.Setenv(envVar, hex.EncodeToString(make([]byte, 16))) // 128-bit, not 256-bit
	_, err = New(envVar, NewMemoryBackend())
	if err == nil {
		t.Fatal("expected error for wrong-length master key")
	}
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
	defer func() {
		_ = reopened.Close()
	}()

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

func TestFileBackendRejectsOversizedEncryptedBlob(t *testing.T) {
	dir := t.TempDir()
	backend, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend returned error: %v", err)
	}
	path, err := backend.keyPath("oversized")
	if err != nil {
		t.Fatalf("keyPath returned error: %v", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	if err := file.Truncate((1 << 20) + 1); err != nil {
		_ = file.Close()
		t.Fatalf("Truncate returned error: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if _, err := backend.Get("oversized"); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("Get oversized blob error = %v, want size-limit rejection", err)
	}
}

func TestFileBackendRejectsFIFOWithoutBlocking(t *testing.T) {
	backend, err := NewFileBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBackend returned error: %v", err)
	}
	path, err := backend.keyPath("fifo")
	if err != nil {
		t.Fatalf("keyPath returned error: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo returned error: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, getErr := backend.Get("fifo")
		result <- getErr
	}()
	select {
	case getErr := <-result:
		if getErr == nil || !strings.Contains(getErr.Error(), "regular") {
			t.Fatalf("Get FIFO error = %v, want regular-file rejection", getErr)
		}
	case <-time.After(100 * time.Millisecond):
		writer, openErr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			t.Fatalf("unblock FIFO reader: %v", openErr)
		}
		_ = writer.Close()
		<-result
		t.Fatal("Get blocked while opening a FIFO")
	}
}

func TestFileBackendPutRejectsOversizedEncryptedBlob(t *testing.T) {
	backend, err := NewFileBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBackend returned error: %v", err)
	}
	if err := backend.Put("oversized", make([]byte, (1<<20)+1)); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("Put oversized blob error = %v, want size-limit rejection", err)
	}
}

func TestFileBackendRoundTripsLargestAcceptedEncryptedBlob(t *testing.T) {
	backend, err := NewFileBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBackend returned error: %v", err)
	}
	want := bytes.Repeat([]byte{0xa5}, maxEncryptedKeyBlobBytes)
	if err := backend.Put("largest-accepted", want); err != nil {
		t.Fatalf("Put largest accepted blob returned error: %v", err)
	}
	got, err := backend.Get("largest-accepted")
	if err != nil {
		t.Fatalf("Get largest accepted blob returned error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("largest accepted encrypted blob changed during round trip")
	}
}

func TestFileBackendConfinesEncodedKeyIDs(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_FILE_BACKEND_CONFINEMENT_KEY"
	t.Setenv(envVar, masterKeyHex)

	root := t.TempDir()
	dir := filepath.Join(root, "keys")
	backend, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend returned error: %v", err)
	}
	store, err := New(envVar, backend)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	ctx := context.Background()
	keyIDs := []string{
		"../outside/key",
		"..",
		"nested/key",
		" key with spaces ",
		strings.Repeat("x", 96),
	}
	for _, keyID := range keyIDs {
		plaintext := []byte("sk-confined-" + keyID)
		if err := store.StoreKey(ctx, keyID, plaintext); err != nil {
			t.Fatalf("StoreKey(%q) returned error: %v", keyID, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != len(keyIDs) {
		t.Fatalf("file count = %d, want %d", len(entries), len(keyIDs))
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("file backend created directory %q", entry.Name())
		}
		if filepath.Dir(filepath.Join(dir, entry.Name())) != dir {
			t.Fatalf("entry %q escaped key store directory", entry.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(root, "outside")); !os.IsNotExist(err) {
		t.Fatalf("unexpected outside path stat error = %v, want not exist", err)
	}
}

func TestNewFileBackendRejectsInsecureDirectoryPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0777); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}
	if _, err := NewFileBackend(dir); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("NewFileBackend error = %v, want insecure-permission rejection", err)
	}
}

func TestFileBackendListRejectsMalformedKeyFilename(t *testing.T) {
	dir := t.TempDir()
	backend, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "%%%.key"), []byte("malformed"), 0600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if _, err := backend.List(); err == nil || !strings.Contains(err.Error(), "filename") {
		t.Fatalf("List error = %v, want malformed filename rejection", err)
	}
}

type reusingBlobBackend struct {
	data  map[string][]byte
	reuse []byte
}

func (b *reusingBlobBackend) Get(keyID string) ([]byte, error) {
	blob, ok := b.data[keyID]
	if !ok {
		return nil, ErrBackendNotFound
	}
	b.reuse = append(b.reuse[:0], blob...)
	return b.reuse, nil
}

func (b *reusingBlobBackend) Put(keyID string, ciphertext []byte) error {
	b.data[keyID] = append([]byte(nil), ciphertext...)
	return nil
}

func (b *reusingBlobBackend) Delete(keyID string) error {
	delete(b.data, keyID)
	return nil
}

func (b *reusingBlobBackend) List() ([]string, error) {
	ids := make([]string, 0, len(b.data))
	for keyID := range b.data {
		ids = append(ids, keyID)
	}
	return ids, nil
}
