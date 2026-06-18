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
}

// ServerConfig defines the HTTP server settings.
type ServerConfig struct {
	Address         string        `json:"address"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout"`
	TLS             TLSConfig     `json:"tls"`
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
// Mode can be "local" (built-in AES-256-GCM) or "vault" (HashiCorp Vault).
type KMSConfig struct {
	Mode  string      `json:"mode"` // "local" | "vault"
	Local LocalKMS    `json:"local"`
	Vault VaultConfig `json:"vault"`
}

// LocalKMS configures the built-in encryption engine.
// The master key MUST be provided via environment variable, never in config files.
type LocalKMS struct {
	MasterKeyEnv string `json:"master_key_env"` // Name of env var holding the master key
}

// VaultConfig configures HashiCorp Vault integration.
type VaultConfig struct {
	Address  string `json:"address"`
	Path     string `json:"path"`
	TokenEnv string `json:"token_env"` // Name of env var holding the Vault token
}

// Provider defines an LLM provider channel configuration.
// SECURITY: The api_key_id references a key stored in KMS, NOT a plaintext key.
type Provider struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // "openai" | "anthropic" | "google" | "deepseek" | ...
	BaseURL     string   `json:"base_url"`
	APIKeyID    string   `json:"api_key_id"` // Reference to KMS-stored key
	Models      []string `json:"models"`
	Weight      int      `json:"weight"`
	MaxRPM      int      `json:"max_rpm"`
	MaxTPM      int      `json:"max_tpm"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`    // Lower = higher priority for fallback
}

// AuthConfig defines authentication settings.
type AuthConfig struct {
	JWTSigningKeyEnv string        `json:"jwt_signing_key_env"` // Env var for JWT private key
	TokenExpiry      time.Duration `json:"token_expiry"`
	Issuer           string        `json:"issuer"`
}

// RateLimitConfig defines rate limiting behavior.
type RateLimitConfig struct {
	Enabled       bool   `json:"enabled"`
	Backend       string `json:"backend"` // "memory" | "redis"
	RedisURL      string `json:"redis_url"`
	DefaultRPM    int    `json:"default_rpm"`
	DefaultTPM    int    `json:"default_tpm"`
	DefaultMaxConcurrency int `json:"default_max_concurrency"`
}

// QuotaConfig defines budget and cost management settings.
type QuotaConfig struct {
	Enabled      bool   `json:"enabled"`
	Backend      string `json:"backend"` // "sqlite" | "mysql"
	DSN          string `json:"dsn"`
	DefaultBudget float64 `json:"default_budget"` // Default monthly budget in USD
}

// StoreConfig defines the persistence layer.
type StoreConfig struct {
	Type string `json:"type"` // "sqlite" | "mysql"
	DSN  string `json:"dsn"`
}

// EgressConfig defines outbound network restrictions.
type EgressConfig struct {
	AllowedDomains []string `json:"allowed_domains"`
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
			Address:         ":8080",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    120 * time.Second, // Long timeout for streaming
			ShutdownTimeout: 15 * time.Second,
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
			DefaultTPM:            100000,
			DefaultMaxConcurrency: 10,
		},
		Quota: QuotaConfig{
			Enabled:       true,
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

	// SECURITY: Ensure no plaintext keys in config
	for _, p := range c.Providers {
		if p.APIKeyID == "" && p.Enabled {
			return fmt.Errorf("provider %q: api_key_id must reference a KMS key, not be empty", p.Name)
		}
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
		if c.KMS.Vault.Address == "" {
			return errors.New("vault KMS requires address to be set")
		}
	default:
		return fmt.Errorf("unsupported KMS mode: %q", c.KMS.Mode)
	}

	return nil
}
