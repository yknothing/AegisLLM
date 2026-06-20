package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	if cfg.RateLimit.RedisURL != "" {
		t.Fatalf("example redis_url = %q, want empty until redis backend exists", cfg.RateLimit.RedisURL)
	}
	if cfg.KMS.Vault.Address != "" || cfg.KMS.Vault.Path != "" || cfg.KMS.Vault.TokenEnv != "" {
		t.Fatalf("example vault config = %+v, want empty until vault backend exists", cfg.KMS.Vault)
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
