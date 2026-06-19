// Package config handles loading and validating the Aegis gateway configuration.
//
// SECURITY NOTE: This package NEVER stores or logs plaintext API keys.
// Provider credentials are referenced by KMS key IDs, not raw values.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the root configuration structure for Aegis.
type Config struct {
	Server    ServerConfig    `json:"server"`
	KMS       KMSConfig       `json:"kms"`
	Providers []Provider      `json:"providers"`
	Auth      AuthConfig      `json:"auth"`
	RateLimit RateLimitConfig `json:"rate_limit"`
	Quota     QuotaConfig     `json:"quota"`
	Store     StoreConfig     `json:"store"`
	Egress    EgressConfig    `json:"egress"`
}

// ServerConfig defines the HTTP server settings.
type ServerConfig struct {
	Address            string        `json:"address"`
	ReadTimeout        time.Duration `json:"read_timeout"`
	WriteTimeout       time.Duration `json:"write_timeout"`
	ShutdownTimeout    time.Duration `json:"shutdown_timeout"`
	MaxRequestBodySize int64         `json:"max_request_body_size"`
	TLS                TLSConfig     `json:"tls"`
}

// TLSConfig defines mutual TLS settings.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	CAFile     string `json:"ca_file"` // For mTLS client verification
	MinVersion string `json:"min_version"`
}

// KMSConfig defines the Key Management System configuration.
// Current runtime supports "local" (built-in AES-256-GCM). "vault" is reserved
// and rejected until the Vault client and failure-mode tests exist.
type KMSConfig struct {
	Mode  string      `json:"mode"` // runtime: "local"; reserved: "vault"
	Local LocalKMS    `json:"local"`
	Vault VaultConfig `json:"vault"`
}

// LocalKMS configures the built-in encryption engine.
// The master key MUST be provided via environment variable, never in config files.
type LocalKMS struct {
	MasterKeyEnv string `json:"master_key_env"` // Name of env var holding the master key
	KeyStorePath string `json:"key_store_path"` // Directory for encrypted local key blobs
}

// VaultConfig reserves HashiCorp Vault integration settings.
// kms.mode="vault" fails fast in the current runtime.
type VaultConfig struct {
	Address  string `json:"address"`
	Path     string `json:"path"`
	TokenEnv string `json:"token_env"` // Name of env var holding the Vault token
}

// Provider defines an LLM provider channel configuration.
// SECURITY: The api_key_id references a key stored in KMS, NOT a plaintext key.
type Provider struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"` // "openai" | "anthropic" | "google" | "deepseek" | ...
	BaseURL  string   `json:"base_url"`
	APIKeyID string   `json:"api_key_id"` // Reference to KMS-stored key
	Models   []string `json:"models"`
	Weight   int      `json:"weight"`
	MaxRPM   int      `json:"max_rpm"`
	MaxTPM   int      `json:"max_tpm"` // Reserved until TPM enforcement exists
	Enabled  bool     `json:"enabled"`
	Priority int      `json:"priority"` // Lower = higher priority for fallback
}

// AuthConfig defines authentication settings.
type AuthConfig struct {
	JWTSigningKeyEnv string        `json:"jwt_signing_key_env"` // Env var for JWT private key
	TokenExpiry      time.Duration `json:"token_expiry"`
	Issuer           string        `json:"issuer"`
}

// RateLimitConfig defines rate limiting behavior.
type RateLimitConfig struct {
	Enabled               bool   `json:"enabled"`
	Backend               string `json:"backend"` // runtime: "memory"; reserved: "redis"
	RedisURL              string `json:"redis_url"`
	DefaultRPM            int    `json:"default_rpm"`
	DefaultTPM            int    `json:"default_tpm"` // Reserved until TPM enforcement exists
	DefaultMaxConcurrency int    `json:"default_max_concurrency"`
}

// QuotaConfig reserves budget and cost management settings.
// quota.enabled=true fails fast until runtime enforcement exists.
type QuotaConfig struct {
	Enabled       bool    `json:"enabled"`
	Backend       string  `json:"backend"` // Reserved durable store backend
	DSN           string  `json:"dsn"`
	DefaultBudget float64 `json:"default_budget"` // Default monthly budget in USD
}

// StoreConfig reserves the persistence layer for future control-plane state.
type StoreConfig struct {
	Type string `json:"type"` // "sqlite" | "mysql"
	DSN  string `json:"dsn"`
}

// EgressConfig defines outbound network restrictions.
type EgressConfig struct {
	AllowedDomains []string `json:"allowed_domains"`
}

// UnmarshalJSON accepts both Go duration nanoseconds and human-readable
// duration strings such as "30s". Missing fields preserve existing defaults.
func (c *ServerConfig) UnmarshalJSON(data []byte) error {
	type serverConfigJSON struct {
		Address            *string         `json:"address"`
		ReadTimeout        json.RawMessage `json:"read_timeout"`
		WriteTimeout       json.RawMessage `json:"write_timeout"`
		ShutdownTimeout    json.RawMessage `json:"shutdown_timeout"`
		MaxRequestBodySize *int64          `json:"max_request_body_size"`
		TLS                *TLSConfig      `json:"tls"`
	}

	var raw serverConfigJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.Address != nil {
		c.Address = *raw.Address
	}
	if raw.ReadTimeout != nil {
		d, err := parseDuration(raw.ReadTimeout, "server.read_timeout")
		if err != nil {
			return err
		}
		c.ReadTimeout = d
	}
	if raw.WriteTimeout != nil {
		d, err := parseDuration(raw.WriteTimeout, "server.write_timeout")
		if err != nil {
			return err
		}
		c.WriteTimeout = d
	}
	if raw.ShutdownTimeout != nil {
		d, err := parseDuration(raw.ShutdownTimeout, "server.shutdown_timeout")
		if err != nil {
			return err
		}
		c.ShutdownTimeout = d
	}
	if raw.MaxRequestBodySize != nil {
		c.MaxRequestBodySize = *raw.MaxRequestBodySize
	}
	if raw.TLS != nil {
		c.TLS = *raw.TLS
	}

	return nil
}

// UnmarshalJSON accepts both Go duration nanoseconds and duration strings.
func (c *AuthConfig) UnmarshalJSON(data []byte) error {
	type authConfigJSON struct {
		JWTSigningKeyEnv *string         `json:"jwt_signing_key_env"`
		TokenExpiry      json.RawMessage `json:"token_expiry"`
		Issuer           *string         `json:"issuer"`
	}

	var raw authConfigJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.JWTSigningKeyEnv != nil {
		c.JWTSigningKeyEnv = *raw.JWTSigningKeyEnv
	}
	if raw.TokenExpiry != nil {
		d, err := parseDuration(raw.TokenExpiry, "auth.token_expiry")
		if err != nil {
			return err
		}
		c.TokenExpiry = d
	}
	if raw.Issuer != nil {
		c.Issuer = *raw.Issuer
	}

	return nil
}

func parseDuration(raw json.RawMessage, field string) (time.Duration, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}

	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		d, parseErr := time.ParseDuration(value)
		if parseErr != nil {
			return 0, fmt.Errorf("%s must be a valid duration: %w", field, parseErr)
		}
		return d, nil
	}

	var nanos int64
	if err := json.Unmarshal(raw, &nanos); err == nil {
		return time.Duration(nanos), nil
	}

	return 0, fmt.Errorf("%s must be a duration string or integer nanoseconds, got %s", field, strconv.Quote(string(raw)))
}

// Load reads and validates the configuration from the given path.
// If path is empty, it attempts to load from default locations.
func Load(path string) (*Config, error) {
	if path == "" {
		// Try default locations in order
		candidates := []string{
			"aegis.json",
			"/etc/aegis/aegis.json",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}

	cfg := defaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// defaultConfig returns a sensible default configuration for standalone mode.
func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Address:            ":8080",
			ReadTimeout:        30 * time.Second,
			WriteTimeout:       120 * time.Second, // Long timeout for streaming
			ShutdownTimeout:    15 * time.Second,
			MaxRequestBodySize: 10 << 20,
		},
		KMS: KMSConfig{
			Mode: "local",
			Local: LocalKMS{
				MasterKeyEnv: "AEGIS_MASTER_KEY",
			},
		},
		Auth: AuthConfig{
			JWTSigningKeyEnv: "AEGIS_JWT_KEY",
			TokenExpiry:      720 * time.Hour, // 30 days
			Issuer:           "aegis",
		},
		RateLimit: RateLimitConfig{
			Enabled:               true,
			Backend:               "memory",
			DefaultRPM:            60,
			DefaultTPM:            0,
			DefaultMaxConcurrency: 10,
		},
		Quota: QuotaConfig{
			Enabled:       false,
			Backend:       "sqlite",
			DSN:           "aegis.db",
			DefaultBudget: 100.0,
		},
		Store: StoreConfig{
			Type: "sqlite",
			DSN:  "aegis.db",
		},
	}
}

// validate checks the configuration for logical errors and security issues.
func (c *Config) validate() error {
	if c.Server.Address == "" {
		return errors.New("server address must not be empty")
	}
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			return errors.New("server TLS requires cert_file and key_file")
		}
		switch c.Server.TLS.MinVersion {
		case "", "1.3", "TLS1.3", "tls1.3":
		default:
			return errors.New("server.tls.min_version currently supports only TLS 1.3")
		}
	}

	enabledProviders := 0

	// SECURITY: Ensure no plaintext keys in config
	for _, p := range c.Providers {
		if !p.Enabled {
			continue
		}
		enabledProviders++
		providerName := p.ID
		if providerName == "" {
			providerName = p.Name
		}
		if p.APIKeyID == "" {
			return fmt.Errorf("provider %q: api_key_id must reference a KMS key, not be empty", providerName)
		}
		if p.MaxTPM > 0 {
			return fmt.Errorf("provider %q: max_tpm is reserved; TPM enforcement is not implemented", providerName)
		}
	}
	if enabledProviders == 0 {
		return errors.New("at least one provider must be enabled")
	}
	if len(c.Egress.AllowedDomains) == 0 {
		return errors.New("egress.allowed_domains must contain at least one host")
	}

	if c.RateLimit.Enabled {
		switch c.RateLimit.Backend {
		case "memory":
		case "redis":
			return errors.New("redis rate limiter backend is not implemented")
		default:
			return fmt.Errorf("unsupported rate_limit backend: %q", c.RateLimit.Backend)
		}
		if c.RateLimit.DefaultTPM > 0 {
			return errors.New("rate_limit.default_tpm is reserved; TPM enforcement is not implemented")
		}
	}

	if c.Quota.Enabled {
		return errors.New("quota enforcement is not implemented; set quota.enabled=false")
	}

	switch c.KMS.Mode {
	case "local":
		if c.KMS.Local.MasterKeyEnv == "" {
			return errors.New("local KMS requires master_key_env to be set")
		}
		// Verify the env var exists (but never log its value)
		if os.Getenv(c.KMS.Local.MasterKeyEnv) == "" {
			return fmt.Errorf("environment variable %q for master key is not set", c.KMS.Local.MasterKeyEnv)
		}
	case "vault":
		return errors.New("vault KMS backend is not implemented")
	default:
		return fmt.Errorf("unsupported KMS mode: %q", c.KMS.Mode)
	}

	return nil
}
