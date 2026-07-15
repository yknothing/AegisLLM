// Package operator implements privileged offline Aegis management use cases.
//
// SECURITY PROPERTIES:
//   - It exposes no network listener and never logs or returns provider-key
//     plaintext.
//   - Provider keys are resolved through configured enabled providers and are
//     zeroed on every return path.
//   - JWT signing material is loaded only for issuance and zeroed immediately.
//   - Revocation and KMS migration delegate durability to their reviewed local
//     storage contracts.
package operator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/kms/factory"
	"github.com/yknothing/AegisLLM/internal/kms/local"
	"github.com/yknothing/AegisLLM/internal/revocation"
	"github.com/yknothing/AegisLLM/internal/utils"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
)

const writerLockTimeout = 2 * time.Second

// Service coordinates offline use cases against one validated configuration.
type Service struct {
	cfg *config.Config
	now func() time.Time
}

// IssueOptions contains supported operator-supplied virtual-key policy.
type IssueOptions struct {
	Subject        string
	Models         []string
	TTL            time.Duration
	MaxRPM         int
	MaxConcurrency int
}

// New creates an offline operator service.
func New(cfg *config.Config) (*Service, error) {
	if cfg == nil {
		return nil, errors.New("operator config is nil")
	}
	if err := config.ValidateEnabledProviderIDs(cfg.Providers); err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, now: time.Now}, nil
}

// ImportProviderKey stores a key under the api_key_id of an enabled configured
// provider. Existing values require explicit replacement approval.
func (s *Service) ImportProviderKey(ctx context.Context, providerID string, plaintext []byte, replace bool) error {
	defer utils.MemZero(plaintext)
	provider, err := s.enabledProvider(providerID)
	if err != nil {
		return err
	}
	if len(plaintext) == 0 {
		return errors.New("provider key input must not be empty")
	}
	store, err := factory.NewOperatorStore(s.cfg.KMS)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	return withKMSFileLock(ctx, s.kmsLockPath(), writerLockTimeout, func() error {
		existing, getErr := store.GetKey(ctx, provider.APIKeyID)
		if getErr == nil {
			existing.Close()
			if !replace {
				return fmt.Errorf("provider %q key already exists; use --replace to overwrite", providerID)
			}
		} else if !errors.Is(getErr, kms.ErrKeyNotFound) {
			return fmt.Errorf("checking existing provider key: %w", getErr)
		}
		return store.StoreKey(ctx, provider.APIKeyID, plaintext)
	})
}

// IssueVirtualKey signs a supported pool token after confirming every model is
// served by at least one enabled provider.
func (s *Service) IssueVirtualKey(opts IssueOptions) (string, *virtualkey.Claims, error) {
	if err := s.validateIssuedModels(opts.Models); err != nil {
		return "", nil, err
	}
	signingKeyValue := os.Getenv(s.cfg.Auth.JWTSigningKeyEnv)
	if signingKeyValue == "" {
		return "", nil, fmt.Errorf("JWT signing key env var %q is not set", s.cfg.Auth.JWTSigningKeyEnv)
	}
	signingKey := []byte(signingKeyValue)
	defer utils.MemZero(signingKey)
	return virtualkey.Issue(signingKey, virtualkey.IssueOptions{
		Subject:        opts.Subject,
		Models:         opts.Models,
		MaxRPM:         opts.MaxRPM,
		MaxConcurrency: opts.MaxConcurrency,
		TTL:            opts.TTL,
		MaxTTL:         s.cfg.Auth.TokenExpiry,
		Issuer:         s.cfg.Auth.Issuer,
		Now:            s.now(),
	})
}

// InitRevocation creates the mandatory empty local revocation snapshot.
func (s *Service) InitRevocation(ctx context.Context) (revocation.CommitResult, error) {
	return s.revocationWriter().Init(ctx, s.now())
}

// RevokeVirtualKey durably revokes a key ID for at least the maximum accepted
// token lifetime plus clock skew.
func (s *Service) RevokeVirtualKey(ctx context.Context, keyID string) (revocation.CommitResult, error) {
	return s.revocationWriter().Revoke(ctx, s.cfg.Auth.Issuer, keyID, s.now(), s.cfg.Auth.TokenExpiry)
}

// InspectKMS validates every encrypted source blob without modifying storage.
func (s *Service) InspectKMS(ctx context.Context) (local.MigrationReport, error) {
	store, err := factory.NewOperatorStore(s.cfg.KMS)
	if err != nil {
		return local.MigrationReport{}, err
	}
	defer func() { _ = store.Close() }()
	var report local.MigrationReport
	err = withKMSFileLock(ctx, s.kmsLockPath(), writerLockTimeout, func() error {
		var inspectErr error
		report, inspectErr = store.InspectFormats(ctx)
		return inspectErr
	})
	return report, err
}

// MigrateKMS creates a new backup directory and migrates legacy blobs only
// after the complete encrypted source set has been validated and backed up.
func (s *Service) MigrateKMS(ctx context.Context, backupDir string) (local.MigrationReport, error) {
	if strings.TrimSpace(backupDir) == "" {
		return local.MigrationReport{}, errors.New("KMS migration backup directory is required")
	}
	store, err := factory.NewOperatorStore(s.cfg.KMS)
	if err != nil {
		return local.MigrationReport{}, err
	}
	defer func() { _ = store.Close() }()
	var report local.MigrationReport
	err = withKMSFileLock(ctx, s.kmsLockPath(), writerLockTimeout, func() error {
		if err := os.MkdirAll(filepath.Dir(backupDir), 0700); err != nil {
			return fmt.Errorf("creating backup parent: %w", err)
		}
		if err := os.Mkdir(backupDir, 0700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return errors.New("KMS migration backup directory must not already exist")
			}
			return fmt.Errorf("creating KMS migration backup directory: %w", err)
		}
		backup, err := local.NewFileBackend(backupDir)
		if err != nil {
			return err
		}
		var migrateErr error
		report, migrateErr = store.MigrateLegacy(ctx, backup)
		return migrateErr
	})
	return report, err
}

func (s *Service) kmsLockPath() string {
	return filepath.Join(s.cfg.KMS.Local.KeyStorePath, ".operator.lock")
}

func (s *Service) revocationWriter() *revocation.Writer {
	return revocation.NewWriter(s.cfg.Auth.Revocation.FilePath, writerLockTimeout)
}

func (s *Service) enabledProvider(providerID string) (*config.Provider, error) {
	for i := range s.cfg.Providers {
		provider := &s.cfg.Providers[i]
		if provider.Enabled && provider.ID == providerID {
			if strings.TrimSpace(provider.APIKeyID) == "" {
				return nil, fmt.Errorf("provider %q has no KMS api_key_id", providerID)
			}
			return provider, nil
		}
	}
	return nil, fmt.Errorf("enabled provider %q is not configured", providerID)
}

func (s *Service) validateIssuedModels(models []string) error {
	configured := make(map[string]struct{})
	for _, provider := range s.cfg.Providers {
		if !provider.Enabled {
			continue
		}
		for _, model := range provider.Models {
			configured[model] = struct{}{}
		}
	}
	if len(models) == 0 {
		return errors.New("at least one configured model is required")
	}
	for _, model := range models {
		if _, ok := configured[strings.TrimSpace(model)]; !ok {
			return fmt.Errorf("model %q is not configured on an enabled provider", model)
		}
	}
	return nil
}
