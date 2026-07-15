package operator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/kms/factory"
	"github.com/yknothing/AegisLLM/internal/revocation"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
)

func TestImportProviderKeyResolvesConfiguredProviderAndProtectsReplace(t *testing.T) {
	cfg := operatorTestConfig(t)
	service, err := New(cfg)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	plaintext := []byte("sk-first-provider-key")
	if err := service.ImportProviderKey(context.Background(), "openai-primary", plaintext, false); err != nil {
		t.Fatalf("ImportProviderKey returned error: %v", err)
	}
	for _, b := range plaintext {
		if b != 0 {
			t.Fatal("ImportProviderKey did not zero plaintext")
		}
	}

	second := []byte("sk-second-provider-key")
	if err := service.ImportProviderKey(context.Background(), "openai-primary", second, false); err == nil || !strings.Contains(err.Error(), "replace") {
		t.Fatalf("second import error = %v, want replace protection", err)
	}
	for _, b := range second {
		if b != 0 {
			t.Fatal("failed ImportProviderKey did not zero plaintext")
		}
	}

	store, err := factory.NewOperatorStore(cfg.KMS)
	if err != nil {
		t.Fatalf("open KMS: %v", err)
	}
	defer func() { _ = store.Close() }()
	key, err := store.GetKey(context.Background(), "openai-key-1")
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	defer key.Close()
	if string(key.Bytes()) != "sk-first-provider-key" {
		t.Fatalf("stored provider key = %q, want first value", key.Bytes())
	}
}

func TestIssueVirtualKeyUsesSharedProductionContract(t *testing.T) {
	cfg := operatorTestConfig(t)
	service, _ := New(cfg)
	now := time.Unix(1_800_000_000, 0).UTC()
	service.now = func() time.Time { return now }

	token, claims, err := service.IssueVirtualKey(IssueOptions{
		Subject:        "client-1",
		Models:         []string{"gpt-4o-mini"},
		TTL:            time.Hour,
		MaxRPM:         10,
		MaxConcurrency: 2,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey returned error: %v", err)
	}
	signingKey := []byte("0123456789abcdef0123456789abcdef")
	validated, err := virtualkey.ValidateAt(token, signingKey, "aegis", 24*time.Hour, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ValidateAt returned error: %v", err)
	}
	if validated.KeyID != claims.KeyID || validated.Subject != "client-1" {
		t.Fatalf("validated claims = %+v, issued = %+v", validated, claims)
	}
}

func TestIssueVirtualKeyRejectsUnconfiguredModel(t *testing.T) {
	service, _ := New(operatorTestConfig(t))
	_, _, err := service.IssueVirtualKey(IssueOptions{
		Subject: "client-1",
		Models:  []string{"not-configured"},
		TTL:     time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "configured") {
		t.Fatalf("IssueVirtualKey model error = %v, want configured-model rejection", err)
	}
}

func TestNewRejectsDuplicateEnabledProviderIDs(t *testing.T) {
	cfg := operatorTestConfig(t)
	duplicate := cfg.Providers[0]
	duplicate.APIKeyID = "other-key"
	cfg.Providers = append(cfg.Providers, duplicate)
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("New duplicate provider error = %v", err)
	}
}

func TestRevocationInitAndRevokeAreVisibleToReader(t *testing.T) {
	cfg := operatorTestConfig(t)
	service, _ := New(cfg)
	service.now = func() time.Time { return time.Now().UTC() }
	if _, err := service.InitRevocation(context.Background()); err != nil {
		t.Fatalf("InitRevocation returned error: %v", err)
	}
	if _, err := service.RevokeVirtualKey(context.Background(), "vk_revoked"); err != nil {
		t.Fatalf("RevokeVirtualKey returned error: %v", err)
	}
	reader, err := revocation.NewReader(cfg.Auth.Revocation.FilePath, time.Hour)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer func() { _ = reader.Close() }()
	revoked, err := reader.Check(context.Background(), "aegis", "vk_revoked")
	if err != nil || !revoked {
		t.Fatalf("Check = revoked=%v err=%v, want true nil", revoked, err)
	}
}

func TestImportProviderKeyRejectsUnknownProviderWithoutTouchingKMS(t *testing.T) {
	cfg := operatorTestConfig(t)
	service, _ := New(cfg)
	plaintext := []byte("sk-unknown")
	err := service.ImportProviderKey(context.Background(), "unknown", plaintext, false)
	if err == nil {
		t.Fatal("ImportProviderKey accepted unknown provider")
	}
	store, openErr := factory.NewOperatorStore(cfg.KMS)
	if openErr != nil {
		t.Fatalf("open KMS: %v", openErr)
	}
	defer func() { _ = store.Close() }()
	if _, getErr := store.GetKey(context.Background(), "openai-key-1"); !errors.Is(getErr, kms.ErrKeyNotFound) {
		t.Fatalf("GetKey error = %v, want no stored key", getErr)
	}
}

func TestImportProviderKeyDoesNotOverwriteUnreadableExistingBlob(t *testing.T) {
	cfg := operatorTestConfig(t)
	service, _ := New(cfg)
	first := []byte("sk-existing")
	if err := service.ImportProviderKey(context.Background(), "openai-primary", first, false); err != nil {
		t.Fatalf("initial import: %v", err)
	}
	entries, err := os.ReadDir(cfg.KMS.Local.KeyStorePath)
	if err != nil {
		t.Fatalf("ReadDir = entries=%d err=%v", len(entries), err)
	}
	var keyFilename string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".key") {
			keyFilename = entry.Name()
		}
	}
	if keyFilename == "" {
		t.Fatal("encrypted key blob was not created")
	}
	path := filepath.Join(cfg.KMS.Local.KeyStorePath, keyFilename)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	before, _ := os.ReadFile(path)
	replacement := []byte("sk-replacement")
	if err := service.ImportProviderKey(context.Background(), "openai-primary", replacement, false); err == nil {
		t.Fatal("import overwrote unreadable existing blob")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("unreadable existing blob changed without --replace")
	}
}

func operatorTestConfig(t *testing.T) *config.Config {
	t.Helper()
	const masterEnv = "TEST_OPERATOR_MASTER"
	const jwtEnv = "TEST_OPERATOR_JWT"
	t.Setenv(masterEnv, hex.EncodeToString(make([]byte, 32)))
	t.Setenv(jwtEnv, "0123456789abcdef0123456789abcdef")
	root := t.TempDir()
	return &config.Config{
		KMS: config.KMSConfig{
			Mode: "local",
			Local: config.LocalKMS{
				MasterKeyEnv: masterEnv,
				KeyStorePath: filepath.Join(root, "keys"),
			},
		},
		Providers: []config.Provider{{
			ID:       "openai-primary",
			APIKeyID: "openai-key-1",
			Models:   []string{"gpt-4o-mini"},
			Enabled:  true,
		}},
		Auth: config.AuthConfig{
			JWTSigningKeyEnv: jwtEnv,
			TokenExpiry:      24 * time.Hour,
			Issuer:           "aegis",
			Revocation: config.RevocationConfig{
				Backend:         "file",
				FilePath:        filepath.Join(root, "revocation", "state.json"),
				RefreshInterval: 500 * time.Millisecond,
			},
		},
	}
}
