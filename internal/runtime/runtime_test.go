package runtime

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestProviderRuntimeRejectsImplicitEgressSubdomain(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Type:     "openai",
				BaseURL:  "https://tenant.api.openai.com",
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
		t.Fatal("providerRuntime accepted an implicit egress subdomain")
	}
}

func TestProviderRuntimeAllowsExplicitEgressWildcardSubdomain(t *testing.T) {
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
		Egress: config.EgressConfig{
			AllowedDomains: []string{"*.openai.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err != nil {
		t.Fatalf("providerRuntime rejected explicit wildcard subdomain: %v", err)
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
	defer func() {
		_ = provider.Close()
	}()

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

func TestLoadJWTSigningKeyEnvRejectsWeakSecret(t *testing.T) {
	const envVar = "TEST_AEGIS_WEAK_JWT_KEY"
	t.Setenv(envVar, "short-secret")

	key, err := loadJWTSigningKeyEnv(envVar)
	if err == nil {
		t.Fatal("loadJWTSigningKeyEnv accepted a weak JWT signing key")
	}
	if key != nil {
		t.Fatal("loadJWTSigningKeyEnv returned key bytes on failure")
	}
	if strings.Contains(err.Error(), "short-secret") {
		t.Fatalf("error leaked JWT signing key value: %v", err)
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("error = %v, want minimum length failure", err)
	}
}

func TestLoadJWTSigningKeyEnvAcceptsStrongSecret(t *testing.T) {
	const envVar = "TEST_AEGIS_STRONG_JWT_KEY"
	secret := "0123456789abcdef0123456789abcdef"
	t.Setenv(envVar, secret)

	key, err := loadJWTSigningKeyEnv(envVar)
	if err != nil {
		t.Fatalf("loadJWTSigningKeyEnv returned error: %v", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	if string(key) != secret {
		t.Fatalf("key bytes = %q, want configured secret", string(key))
	}
}

func TestNewServerRejectsUnsupportedRuntimeControls(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name: "token expiry",
			mutate: func(cfg *config.Config) {
				cfg.Auth.TokenExpiry = 0
			},
			wantErr: "auth.token_expiry must be positive",
		},
		{
			name: "quota",
			mutate: func(cfg *config.Config) {
				cfg.Quota.Enabled = true
			},
			wantErr: "quota enforcement is not implemented",
		},
		{
			name: "quota backend",
			mutate: func(cfg *config.Config) {
				cfg.Quota.Backend = "sqlite"
			},
			wantErr: "quota.backend is reserved",
		},
		{
			name: "quota dsn",
			mutate: func(cfg *config.Config) {
				cfg.Quota.DSN = "aegis.db"
			},
			wantErr: "quota.dsn is reserved",
		},
		{
			name: "quota default budget",
			mutate: func(cfg *config.Config) {
				cfg.Quota.DefaultBudget = 100.0
			},
			wantErr: "quota.default_budget is reserved",
		},
		{
			name: "negative quota default budget",
			mutate: func(cfg *config.Config) {
				cfg.Quota.DefaultBudget = -1.0
			},
			wantErr: "quota.default_budget must not be negative",
		},
		{
			name: "store type",
			mutate: func(cfg *config.Config) {
				cfg.Store.Type = "sqlite"
			},
			wantErr: "store persistence config is reserved",
		},
		{
			name: "store dsn",
			mutate: func(cfg *config.Config) {
				cfg.Store.DSN = "aegis.db"
			},
			wantErr: "store persistence config is reserved",
		},
		{
			name: "vault config",
			mutate: func(cfg *config.Config) {
				cfg.KMS.Vault.Address = "https://vault.internal:8200"
			},
			wantErr: "kms.vault is reserved",
		},
		{
			name: "unknown rate limit backend",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "memcached"
			},
			wantErr: `unsupported rate_limit backend: "memcached"`,
		},
		{
			name: "disabled redis rate limit backend",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "redis"
			},
			wantErr: "redis rate limiter backend is not implemented",
		},
		{
			name: "disabled default TPM",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "memory"
				cfg.RateLimit.DefaultTPM = 1000
			},
			wantErr: "TPM enforcement is not implemented",
		},
		{
			name: "redis url",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Backend = "memory"
				cfg.RateLimit.RedisURL = "redis://localhost:6379/0"
			},
			wantErr: "rate_limit.redis_url is reserved",
		},
		{
			name: "disabled negative default RPM",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "memory"
				cfg.RateLimit.DefaultRPM = -1
			},
			wantErr: "rate_limit.default_rpm must not be negative",
		},
		{
			name: "provider RPM",
			mutate: func(cfg *config.Config) {
				cfg.Providers[0].MaxRPM = 100
			},
			wantErr: "provider RPM enforcement is not implemented",
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

func TestRuntimeMiddlewareOrder(t *testing.T) {
	tests := []struct {
		name             string
		rateLimitEnabled bool
		want             []string
	}{
		{
			name:             "with rate limit",
			rateLimitEnabled: true,
			want: []string{
				runtimeStepAuth,
				runtimeStepRateLimit,
				runtimeStepPIIRedaction,
				runtimeStepRouter,
				runtimeStepKMS,
				runtimeStepAdapter,
				runtimeStepProxy,
			},
		},
		{
			name:             "without rate limit",
			rateLimitEnabled: false,
			want: []string{
				runtimeStepAuth,
				runtimeStepPIIRedaction,
				runtimeStepRouter,
				runtimeStepKMS,
				runtimeStepAdapter,
				runtimeStepProxy,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runtimeMiddlewareOrder(tt.rateLimitEnabled); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("runtimeMiddlewareOrder(%t) = %v, want %v", tt.rateLimitEnabled, got, tt.want)
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
		Auth: config.AuthConfig{
			TokenExpiry: 24 * time.Hour,
		},
	}
}
