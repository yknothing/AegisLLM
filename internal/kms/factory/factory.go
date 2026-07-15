// Package factory centralizes concrete KMS construction for the server runtime
// and offline operator commands.
//
// SECURITY: Operator mutation always requires a durable file backend. The
// runtime may use memory only for explicit programmatic smoke/test configs.
package factory

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/kms/local"
)

// New creates the configured runtime KMS provider.
func New(cfg config.KMSConfig) (kms.Provider, error) {
	switch cfg.Mode {
	case "local":
		backend := local.Backend(local.NewMemoryBackend())
		if cfg.Local.KeyStorePath != "" {
			fileBackend, err := local.NewFileBackend(cfg.Local.KeyStorePath)
			if err != nil {
				return nil, err
			}
			backend = fileBackend
		}
		return local.NewWithMinimumEnvelopeVersion(cfg.Local.MasterKeyEnv, backend, minimumEnvelopeVersion(cfg.Local.MinimumEnvelopeVersion))
	case "vault":
		return nil, errors.New("vault KMS backend is not implemented")
	default:
		return nil, fmt.Errorf("unsupported KMS mode: %q", cfg.Mode)
	}
}

// NewOperatorStore creates the durable local store used by privileged offline
// commands. It rejects volatile memory storage.
func NewOperatorStore(cfg config.KMSConfig) (*local.Store, error) {
	if cfg.Mode != "local" {
		return nil, fmt.Errorf("operator KMS requires local mode, got %q", cfg.Mode)
	}
	if strings.TrimSpace(cfg.Local.KeyStorePath) == "" {
		return nil, errors.New("operator KMS requires kms.local.key_store_path")
	}
	backend, err := local.NewFileBackend(cfg.Local.KeyStorePath)
	if err != nil {
		return nil, err
	}
	return local.NewWithMinimumEnvelopeVersion(cfg.Local.MasterKeyEnv, backend, minimumEnvelopeVersion(cfg.Local.MinimumEnvelopeVersion))
}

func minimumEnvelopeVersion(configured int) int {
	if configured == 0 {
		return 1
	}
	return configured
}
