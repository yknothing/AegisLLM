package config

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsUnknownFieldsAtEveryConfigBoundary(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "root",
			data: bytes.Replace(example, []byte(`"server": {`), []byte(`"unexpected_root": true, "server": {`), 1),
		},
		{
			name: "server",
			data: bytes.Replace(example, []byte(`"address": ":8080",`), []byte(`"adress": ":9090", "address": ":8080",`), 1),
		},
		{
			name: "tls",
			data: bytes.Replace(example, []byte(`"enabled": false,`), []byte(`"enabeld": true, "enabled": false,`), 1),
		},
		{
			name: "auth",
			data: bytes.Replace(example, []byte(`"issuer": "aegis"`), []byte(`"isuer": "aegis", "issuer": "aegis"`), 1),
		},
		{
			name: "provider",
			data: bytes.Replace(example, []byte(`"name": "OpenAI Primary",`), []byte(`"naem": "OpenAI Primary", "name": "OpenAI Primary",`), 1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "aegis.json")
			if err := os.WriteFile(path, tt.data, 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("Load error = %v, want unknown field rejection", err)
			}
		})
	}
}

func TestLoadRejectsEmptyAuthIssuer(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	example = bytes.Replace(example, []byte(`"issuer": "aegis"`), []byte(`"issuer": ""`), 1)

	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, example, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "auth.issuer must not be empty") {
		t.Fatalf("Load error = %v, want empty issuer rejection", err)
	}
}

func TestLoadParsesDurationStrings(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	path := filepath.Join(t.TempDir(), "aegis.json")
	data := []byte(`{
			"server": {
				"address": ":9090",
				"read_timeout": "5s",
			"write_timeout": "2m",
			"shutdown_timeout": "10s",
			"max_request_body_size": 1024
		},
		"kms": {
			"mode": "local",
			"local": {
				"master_key_env": "AEGIS_MASTER_KEY",
				"key_store_path": "aegis.keys"
			}
		},
			"auth": {
				"jwt_signing_key_env": "AEGIS_JWT_KEY",
				"token_expiry": "24h",
				"issuer": "aegis"
			},
			"providers": [
				{
					"id": "openai-primary",
					"name": "OpenAI Primary",
					"type": "openai",
					"base_url": "https://api.openai.com",
					"api_key_id": "openai-key-1",
					"models": ["gpt-4o-mini"],
					"enabled": true
				}
			],
			"quota": {
				"enabled": false
			},
			"egress": {
				"allowed_domains": ["api.openai.com"]
			}
		}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.ReadTimeout != 5*time.Second {
		t.Fatalf("read timeout = %v, want 5s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 2*time.Minute {
		t.Fatalf("write timeout = %v, want 2m", cfg.Server.WriteTimeout)
	}
	if cfg.Auth.TokenExpiry != 24*time.Hour {
		t.Fatalf("token expiry = %v, want 24h", cfg.Auth.TokenExpiry)
	}
	if cfg.Server.MaxRequestBodySize != 1024 {
		t.Fatalf("max body size = %d, want 1024", cfg.Server.MaxRequestBodySize)
	}
	if cfg.KMS.Local.KeyStorePath != "aegis.keys" {
		t.Fatalf("key store path = %q, want aegis.keys", cfg.KMS.Local.KeyStorePath)
	}
	if cfg.KMS.Local.MinimumEnvelopeVersion != 2 {
		t.Fatalf("minimum envelope version = %d, want strict v2", cfg.KMS.Local.MinimumEnvelopeVersion)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	cfg, err := Load(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("Load example config returned error: %v", err)
	}
	if cfg.RateLimit.DefaultTPM != 0 {
		t.Fatalf("example default_tpm = %d, want 0 until TPM enforcement exists", cfg.RateLimit.DefaultTPM)
	}
	if cfg.Auth.TokenExpiry > 24*time.Hour {
		t.Fatalf("example token expiry = %v, want no more than 24h for the standalone baseline", cfg.Auth.TokenExpiry)
	}
	if cfg.RateLimit.RedisURL != "" {
		t.Fatalf("example redis_url = %q, want empty until redis backend exists", cfg.RateLimit.RedisURL)
	}
	if cfg.KMS.Vault.Address != "" || cfg.KMS.Vault.Path != "" || cfg.KMS.Vault.TokenEnv != "" {
		t.Fatalf("example vault config = %+v, want empty until vault backend exists", cfg.KMS.Vault)
	}
	if cfg.KMS.Local.MinimumEnvelopeVersion != 2 {
		t.Fatalf("example minimum envelope version = %d, want 2", cfg.KMS.Local.MinimumEnvelopeVersion)
	}
	for _, provider := range cfg.Providers {
		if provider.MaxRPM != 0 {
			t.Fatalf("example provider %q max_rpm = %d, want 0 until provider RPM enforcement exists", provider.ID, provider.MaxRPM)
		}
	}
	if cfg.Quota.Enabled {
		t.Fatal("example config enabled quota before runtime enforcement exists")
	}
	if cfg.Quota.Backend != "" || cfg.Quota.DSN != "" || cfg.Quota.DefaultBudget != 0 {
		t.Fatalf("example quota reserved fields = backend=%q dsn=%q budget=%f, want empty/zero until quota enforcement exists", cfg.Quota.Backend, cfg.Quota.DSN, cfg.Quota.DefaultBudget)
	}
	if cfg.Store.Type != "" || cfg.Store.DSN != "" {
		t.Fatalf("example store reserved fields = type=%q dsn=%q, want empty until control-plane store exists", cfg.Store.Type, cfg.Store.DSN)
	}
}

func TestLoadExampleConfigIncludesDurableFileRevocation(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	cfg, err := Load(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("Load example config returned error: %v", err)
	}
	if cfg.Auth.Revocation.Backend != "file" {
		t.Fatalf("revocation backend = %q, want file", cfg.Auth.Revocation.Backend)
	}
	if cfg.Auth.Revocation.FilePath != "aegis.revocations.json" {
		t.Fatalf("revocation file path = %q, want aegis.revocations.json", cfg.Auth.Revocation.FilePath)
	}
	if cfg.Auth.Revocation.RefreshInterval != 500*time.Millisecond {
		t.Fatalf("revocation refresh interval = %v, want 500ms", cfg.Auth.Revocation.RefreshInterval)
	}
}

func TestLoadForOperatorDoesNotRequireUnrelatedSecretEnvironment(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", "")

	cfg, err := LoadForOperator(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("LoadForOperator returned error without master-key env: %v", err)
	}
	if cfg.KMS.Local.MasterKeyEnv != "AEGIS_MASTER_KEY" {
		t.Fatalf("master key env = %q, want configured env name", cfg.KMS.Local.MasterKeyEnv)
	}
}

func TestDefaultConfigUsesTwentyFourHourTokenTTLAndFileRevocation(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Auth.TokenExpiry != 24*time.Hour {
		t.Fatalf("default token expiry = %v, want 24h", cfg.Auth.TokenExpiry)
	}
	if cfg.Auth.Revocation.Backend != "file" || cfg.Auth.Revocation.FilePath == "" {
		t.Fatalf("default revocation = %+v, want durable file backend", cfg.Auth.Revocation)
	}
}

func TestLoadRejectsInvalidRevocationConfig(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	tests := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{name: "backend", old: `"backend": "file"`, new: `"backend": "memory"`, wantErr: "unsupported auth.revocation backend"},
		{name: "empty path", old: `"file_path": "aegis.revocations.json"`, new: `"file_path": ""`, wantErr: "auth.revocation.file_path must not be empty"},
		{name: "too slow", old: `"refresh_interval": "500ms"`, new: `"refresh_interval": "10s"`, wantErr: "auth.revocation.refresh_interval must not exceed"},
		{name: "unknown field", old: `"backend": "file"`, new: `"backend": "file", "unknown": true`, wantErr: "unknown field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Replace(example, []byte(tt.old), []byte(tt.new), 1)
			path := filepath.Join(t.TempDir(), "aegis.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEnabledProviderIDsRejectsEmptyAndDuplicateIDs(t *testing.T) {
	tests := []struct {
		name      string
		providers []Provider
	}{
		{name: "empty", providers: []Provider{{Enabled: true, ID: ""}}},
		{name: "duplicate", providers: []Provider{{Enabled: true, ID: "same"}, {Enabled: true, ID: "same"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEnabledProviderIDs(tt.providers); err == nil {
				t.Fatal("ValidateEnabledProviderIDs accepted invalid provider IDs")
			}
		})
	}
}

func TestLoadRejectsInvalidMinimumEnvelopeVersion(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	data := bytes.Replace(example, []byte(`"minimum_envelope_version": 2`), []byte(`"minimum_envelope_version": 3`), 1)
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "minimum_envelope_version must be 1 or 2") {
		t.Fatalf("Load error = %v, want envelope-version rejection", err)
	}
}

func TestLoadRejectsProviderAPIKeyIDAboveKMSBound(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
	example, err := os.ReadFile(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	data := bytes.Replace(example, []byte(`"api_key_id": "openai-key-1"`), []byte(`"api_key_id": "`+strings.Repeat("k", 129)+`"`), 1)
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "api_key_id must not exceed 128 bytes") {
		t.Fatalf("Load error = %v, want KMS key-ID bound rejection", err)
	}
}

func TestLoadRejectsQuotaUntilRuntimeEnforcementExists(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	path := writeConfig(t, `{
		"kms": {
			"mode": "local",
			"local": {"master_key_env": "AEGIS_MASTER_KEY"}
		},
		"providers": [
			{
				"id": "openai-primary",
				"name": "OpenAI Primary",
				"type": "openai",
				"base_url": "https://api.openai.com",
				"api_key_id": "openai-key-1",
				"models": ["gpt-4o-mini"],
				"enabled": true
			}
		],
		"quota": {"enabled": true},
		"egress": {"allowed_domains": ["api.openai.com"]}
	}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "quota enforcement is not implemented") {
		t.Fatalf("Load error = %v, want quota enforcement failure", err)
	}
}

func TestLoadRejectsReservedPersistenceConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "quota backend",
			config: `"quota": {
				"enabled": false,
				"backend": "sqlite"
			}`,
			wantErr: "quota.backend is reserved",
		},
		{
			name: "quota dsn",
			config: `"quota": {
				"enabled": false,
				"dsn": "aegis.db"
			}`,
			wantErr: "quota.dsn is reserved",
		},
		{
			name: "quota default budget",
			config: `"quota": {
				"enabled": false,
				"default_budget": 100.0
			}`,
			wantErr: "quota.default_budget is reserved",
		},
		{
			name: "zero quota default budget field present",
			config: `"quota": {
				"enabled": false,
				"default_budget": 0
			}`,
			wantErr: "quota.default_budget is reserved",
		},
		{
			name: "store type",
			config: `"quota": {"enabled": false},
				"store": {
					"type": "sqlite"
				}`,
			wantErr: "store persistence config is reserved",
		},
		{
			name: "store dsn",
			config: `"quota": {"enabled": false},
				"store": {
					"dsn": "aegis.db"
				}`,
			wantErr: "store persistence config is reserved",
		},
		{
			name: "empty store field present",
			config: `"quota": {"enabled": false},
				"store": {}`,
			wantErr: "store persistence config is reserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				`+tt.config+`,
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsNonPositiveAuthTokenExpiry(t *testing.T) {
	tests := []struct {
		name        string
		tokenExpiry string
	}{
		{name: "zero", tokenExpiry: "0s"},
		{name: "negative", tokenExpiry: "-1s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"auth": {
					"jwt_signing_key_env": "AEGIS_JWT_KEY",
					"token_expiry": "`+tt.tokenExpiry+`",
					"issuer": "aegis"
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "auth.token_expiry must be positive") {
				t.Fatalf("Load error = %v, want auth.token_expiry failure", err)
			}
		})
	}
}

func TestLoadRejectsInvalidServerBounds(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		wantErr string
	}{
		{
			name:    "zero read timeout",
			server:  serverBoundsConfig("0s", "120s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.read_timeout must be positive",
		},
		{
			name:    "negative read timeout",
			server:  serverBoundsConfig("-1s", "120s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.read_timeout must be positive",
		},
		{
			name:    "zero write timeout",
			server:  serverBoundsConfig("30s", "0s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.write_timeout must be positive",
		},
		{
			name:    "negative write timeout",
			server:  serverBoundsConfig("30s", "-1s", "15s", DefaultMaxRequestBodySize),
			wantErr: "server.write_timeout must be positive",
		},
		{
			name:    "zero shutdown timeout",
			server:  serverBoundsConfig("30s", "120s", "0s", DefaultMaxRequestBodySize),
			wantErr: "server.shutdown_timeout must be positive",
		},
		{
			name:    "negative shutdown timeout",
			server:  serverBoundsConfig("30s", "120s", "-1s", DefaultMaxRequestBodySize),
			wantErr: "server.shutdown_timeout must be positive",
		},
		{
			name:    "zero body size",
			server:  serverBoundsConfig("30s", "120s", "15s", 0),
			wantErr: "server.max_request_body_size must be positive",
		},
		{
			name:    "negative body size",
			server:  serverBoundsConfig("30s", "120s", "15s", -1),
			wantErr: "server.max_request_body_size must be positive",
		},
		{
			name:    "body size above maximum",
			server:  serverBoundsConfig("30s", "120s", "15s", MaxRequestBodySizeLimit+1),
			wantErr: "server.max_request_body_size must not exceed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				"server": {
					"address": ":9090",
					`+tt.server+`
				},
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsReservedRateControls(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "provider max_rpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"max_rpm": 100,
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "provider RPM enforcement is not implemented",
		},
		{
			name: "provider max_tpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"max_tpm": 1000,
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "TPM enforcement is not implemented",
		},
		{
			name: "default_tpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"rate_limit": {
					"enabled": true,
					"backend": "memory",
					"default_tpm": 1000
				},
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "TPM enforcement is not implemented",
		},
		{
			name: "redis url field present",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"rate_limit": {
					"enabled": true,
					"backend": "memory",
					"redis_url": ""
				},
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "rate_limit.redis_url is reserved",
		},
		{
			name: "vault config field present",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"},
					"vault": {}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "kms.vault is reserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, tt.config)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsNegativeRateLimitValues(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "provider max_rpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"max_rpm": -1,
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "max_rpm must not be negative",
		},
		{
			name: "default_rpm",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"rate_limit": {
					"enabled": true,
					"backend": "memory",
					"default_rpm": -1
				},
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "rate_limit.default_rpm must not be negative",
		},
		{
			name: "disabled default_rpm",
			config: `{
					"kms": {
						"mode": "local",
						"local": {"master_key_env": "AEGIS_MASTER_KEY"}
					},
					"providers": [
						{
							"id": "openai-primary",
							"name": "OpenAI Primary",
							"type": "openai",
							"base_url": "https://api.openai.com",
							"api_key_id": "openai-key-1",
							"models": ["gpt-4o-mini"],
							"enabled": true
						}
					],
					"rate_limit": {
						"enabled": false,
						"backend": "memory",
						"default_rpm": -1
					},
					"quota": {"enabled": false},
					"egress": {"allowed_domains": ["api.openai.com"]}
				}`,
			wantErr: "rate_limit.default_rpm must not be negative",
		},
		{
			name: "default_max_concurrency",
			config: `{
				"kms": {
					"mode": "local",
					"local": {"master_key_env": "AEGIS_MASTER_KEY"}
				},
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"rate_limit": {
					"enabled": true,
					"backend": "memory",
					"default_max_concurrency": -1
				},
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`,
			wantErr: "rate_limit.default_max_concurrency must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, tt.config)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsUnsupportedRuntimeBackends(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "redis",
			config: `"rate_limit": {
				"enabled": true,
				"backend": "redis"
			}`,
			wantErr: "redis rate limiter backend is not implemented",
		},
		{
			name: "disabled redis",
			config: `"rate_limit": {
					"enabled": false,
					"backend": "redis"
				}`,
			wantErr: "redis rate limiter backend is not implemented",
		},
		{
			name: "unknown rate limiter",
			config: `"rate_limit": {
				"enabled": true,
				"backend": "memcached"
			}`,
			wantErr: `unsupported rate_limit backend: "memcached"`,
		},
		{
			name: "vault",
			config: `"kms": {
				"mode": "vault"
			}`,
			wantErr: "vault KMS backend is not implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))
			path := writeConfig(t, `{
				`+tt.config+`,
				"providers": [
					{
						"id": "openai-primary",
						"name": "OpenAI Primary",
						"type": "openai",
						"base_url": "https://api.openai.com",
						"api_key_id": "openai-key-1",
						"models": ["gpt-4o-mini"],
						"enabled": true
					}
				],
				"quota": {"enabled": false},
				"egress": {"allowed_domains": ["api.openai.com"]}
			}`)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aegis.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func serverBoundsConfig(readTimeout, writeTimeout, shutdownTimeout string, maxRequestBodySize int64) string {
	return fmt.Sprintf(`"read_timeout": %q,
		"write_timeout": %q,
		"shutdown_timeout": %q,
		"max_request_body_size": %d`, readTimeout, writeTimeout, shutdownTimeout, maxRequestBodySize)
}
