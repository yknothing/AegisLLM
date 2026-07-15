package factory

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/config"
)

func TestNewOperatorStoreRequiresDurableLocalPath(t *testing.T) {
	t.Setenv("TEST_FACTORY_MASTER", hex.EncodeToString(make([]byte, 32)))
	_, err := NewOperatorStore(config.KMSConfig{
		Mode:  "local",
		Local: config.LocalKMS{MasterKeyEnv: "TEST_FACTORY_MASTER"},
	})
	if err == nil || !strings.Contains(err.Error(), "key_store_path") {
		t.Fatalf("NewOperatorStore error = %v, want durable path rejection", err)
	}
}

func TestNewOperatorStoreUsesConfiguredFileBackend(t *testing.T) {
	t.Setenv("TEST_FACTORY_FILE_MASTER", hex.EncodeToString(make([]byte, 32)))
	store, err := NewOperatorStore(config.KMSConfig{
		Mode: "local",
		Local: config.LocalKMS{
			MasterKeyEnv: "TEST_FACTORY_FILE_MASTER",
			KeyStorePath: filepath.Join(t.TempDir(), "keys"),
		},
	})
	if err != nil {
		t.Fatalf("NewOperatorStore returned error: %v", err)
	}
	defer func() { _ = store.Close() }()
}
