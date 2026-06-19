package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
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
			"local": { "master_key_env": "AEGIS_MASTER_KEY" }
		},
		"auth": {
			"jwt_signing_key_env": "AEGIS_JWT_KEY",
			"token_expiry": "24h",
			"issuer": "aegis"
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
}
