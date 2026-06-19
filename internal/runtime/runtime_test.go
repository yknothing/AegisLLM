package runtime

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/config"
)

func TestProviderRuntimeAcceptsExplicitEgressDomains(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Name:     "OpenAI Primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}

	channels, keyMapping, providerTypes, err := providerRuntime(cfg)
	if err != nil {
		t.Fatalf("providerRuntime returned error: %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("channels len = %d, want 1", len(channels))
	}
	if keyMapping["openai-primary"] != "openai-key-1" {
		t.Fatalf("key mapping was not populated")
	}
	if providerTypes["openai-primary"] != "openai" {
		t.Fatalf("provider type was not populated")
	}
}

func TestProviderRuntimeRejectsHTTPProvider(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "unsafe",
				Type:     "openai",
				BaseURL:  "http://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted a non-HTTPS provider")
	}
}

func TestProviderRuntimeRequiresExplicitEgressAllowlist(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted an empty egress allowlist")
	}
}

func TestProviderRuntimeRejectsUnsupportedProviderType(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "anthropic-primary",
				Type:     "anthropic",
				BaseURL:  "https://api.anthropic.com",
				APIKeyID: "anthropic-key-1",
				Models:   []string{"claude-sonnet-4-20250514"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.anthropic.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted an unsupported provider type")
	}
}

func TestNewKMSProviderUsesFileBackend(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_RUNTIME_FILE_KMS_KEY"
	t.Setenv(envVar, masterKeyHex)

	dir := filepath.Join(t.TempDir(), "keys")
	provider, err := newKMSProvider(config.KMSConfig{
		Mode: "local",
		Local: config.LocalKMS{
			MasterKeyEnv: envVar,
			KeyStorePath: dir,
		},
	})
	if err != nil {
		t.Fatalf("newKMSProvider returned error: %v", err)
	}
	defer provider.Close()

	if err := provider.StoreKey(context.Background(), "openai-key-1", []byte("sk-runtime-file-key")); err != nil {
		t.Fatalf("StoreKey returned error: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("file count = %d, want 1", len(entries))
	}
}

func TestNewServerRejectsUnsupportedRuntimeControls(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name: "quota",
			mutate: func(cfg *config.Config) {
				cfg.Quota.Enabled = true
			},
			wantErr: "quota enforcement is not implemented",
		},
		{
			name: "unknown rate limit backend",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = true
				cfg.RateLimit.Backend = "memcached"
			},
			wantErr: `unsupported rate_limit backend: "memcached"`,
		},
		{
			name: "default TPM",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = true
				cfg.RateLimit.Backend = "memory"
				cfg.RateLimit.DefaultTPM = 1000
			},
			wantErr: "TPM enforcement is not implemented",
		},
		{
			name: "provider TPM",
			mutate: func(cfg *config.Config) {
				cfg.Providers[0].MaxTPM = 1000
			},
			wantErr: "TPM enforcement is not implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := minimalRuntimeConfig()
			tt.mutate(cfg)

			_, err := NewServer(cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewServer error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func minimalRuntimeConfig() *config.Config {
	return &config.Config{
		KMS: config.KMSConfig{
			Mode: "local",
			Local: config.LocalKMS{
				MasterKeyEnv: "TEST_AEGIS_RUNTIME_MASTER_KEY",
			},
		},
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Name:     "OpenAI Primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:               true,
			Backend:               "memory",
			DefaultRPM:            60,
			DefaultMaxConcurrency: 10,
		},
		Quota: config.QuotaConfig{
			Enabled: false,
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}
}
