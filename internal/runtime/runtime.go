// Package runtime wires configuration into the concrete Aegis runtime.
//
// SECURITY: This package is the composition root. It is responsible for
// preserving the security-critical middleware order and for closing long-lived
// secret material on shutdown.
package runtime

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/egress"
	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/kms/local"
	"github.com/yknothing/AegisLLM/internal/middleware"
	"github.com/yknothing/AegisLLM/internal/proxy"
	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/utils"
)

// NewServer builds a runnable Aegis server with middleware registered in the
// ADR-004 order.
func NewServer(cfg *config.Config, logger *slog.Logger) (*server.Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		return nil, err
	}

	kmsProvider, err := newKMSProvider(cfg.KMS)
	if err != nil {
		return nil, err
	}

	signingKey, err := loadJWTSigningKeyEnv(cfg.Auth.JWTSigningKeyEnv)
	if err != nil {
		_ = kmsProvider.Close()
		return nil, err
	}

	channels, poolKeyMapping, providerTypes, err := providerRuntime(cfg)
	if err != nil {
		utils.MemZero(signingKey)
		_ = kmsProvider.Close()
		return nil, err
	}

	engine := proxy.NewEngine(proxy.StreamConfig{
		MaxRequestBodySize: cfg.Server.MaxRequestBodySize,
		StreamTimeout:      cfg.Server.WriteTimeout,
		AllowedDomains:     cfg.Egress.AllowedDomains,
	})

	opts, err := runtimeMiddlewareOptions(cfg, signingKey, kmsProvider, channels, poolKeyMapping, providerTypes, engine)
	if err != nil {
		utils.MemZero(signingKey)
		_ = kmsProvider.Close()
		return nil, err
	}
	opts = append(opts, server.WithShutdownHook(func() error {
		utils.MemZero(signingKey)
		return kmsProvider.Close()
	}))

	srv, err := server.New(cfg, logger, opts...)
	if err != nil {
		utils.MemZero(signingKey)
		_ = kmsProvider.Close()
		return nil, err
	}
	return srv, nil
}

const (
	runtimeStepAuth         = "auth"
	runtimeStepRateLimit    = "rate_limit"
	runtimeStepPIIRedaction = "pii_redaction"
	runtimeStepRouter       = "router"
	runtimeStepKMS          = "kms"
	runtimeStepAdapter      = "adapter"
	runtimeStepProxy        = "proxy"
)

func runtimeMiddlewareOrder(rateLimitEnabled bool) []string {
	order := []string{runtimeStepAuth}
	if rateLimitEnabled {
		order = append(order, runtimeStepRateLimit)
	}
	return append(order,
		runtimeStepPIIRedaction,
		runtimeStepRouter,
		runtimeStepKMS,
		runtimeStepAdapter,
		runtimeStepProxy,
	)
}

func runtimeMiddlewareOptions(
	cfg *config.Config,
	signingKey []byte,
	kmsProvider kms.Provider,
	channels []middleware.ProviderChannel,
	poolKeyMapping map[string]string,
	providerTypes map[string]string,
	engine *proxy.Engine,
) ([]server.Option, error) {
	order := runtimeMiddlewareOrder(cfg.RateLimit.Enabled)
	opts := make([]server.Option, 0, len(order))
	for _, step := range order {
		switch step {
		case runtimeStepAuth:
			opts = append(opts, server.WithMiddleware(middleware.Auth(middleware.AuthConfig{
				SigningKey: signingKey,
				Issuer:     cfg.Auth.Issuer,
				Expiry:     cfg.Auth.TokenExpiry,
				Revocation: middleware.NewMemoryRevocationStore(),
			})))
		case runtimeStepRateLimit:
			opts = append(opts, server.WithMiddleware(middleware.RateLimiter(middleware.RateLimitConfig{
				Backend:        cfg.RateLimit.Backend,
				RedisURL:       cfg.RateLimit.RedisURL,
				DefaultRPM:     cfg.RateLimit.DefaultRPM,
				DefaultTPM:     cfg.RateLimit.DefaultTPM,
				DefaultMaxConc: cfg.RateLimit.DefaultMaxConcurrency,
			})))
		case runtimeStepPIIRedaction:
			opts = append(opts, server.WithMiddleware(middleware.PIIRedaction(middleware.RedactionConfig{
				Mode:               middleware.ModeRedact,
				MaxRequestBodySize: cfg.Server.MaxRequestBodySize,
			})))
		case runtimeStepRouter:
			opts = append(opts, server.WithMiddleware(middleware.Router(middleware.RouterConfig{
				Channels:           channels,
				MaxRequestBodySize: cfg.Server.MaxRequestBodySize,
			})))
		case runtimeStepKMS:
			opts = append(opts, server.WithMiddleware(middleware.KMSInjector(middleware.KMSMiddlewareConfig{
				Provider:       kmsProvider,
				PoolKeyMapping: poolKeyMapping,
			})))
		case runtimeStepAdapter:
			opts = append(opts, server.WithMiddleware(middleware.Adapter(
				middleware.NewAdapterRegistry(),
				providerTypes,
				cfg.Server.MaxRequestBodySize,
			)))
		case runtimeStepProxy:
			opts = append(opts, server.WithMiddleware(middleware.Proxy(engine)))
		default:
			return nil, fmt.Errorf("unknown runtime middleware step %q", step)
		}
	}
	return opts, nil
}

func validateRuntimeConfig(cfg *config.Config) error {
	if cfg.Auth.TokenExpiry <= 0 {
		return fmt.Errorf("auth.token_expiry must be positive")
	}
	switch cfg.RateLimit.Backend {
	case "memory":
	case "redis":
		return fmt.Errorf("redis rate limiter backend is not implemented")
	default:
		return fmt.Errorf("unsupported rate_limit backend: %q", cfg.RateLimit.Backend)
	}
	if cfg.RateLimit.DefaultRPM < 0 {
		return fmt.Errorf("rate_limit.default_rpm must not be negative")
	}
	if cfg.RateLimit.DefaultTPM < 0 {
		return fmt.Errorf("rate_limit.default_tpm must not be negative")
	}
	if cfg.RateLimit.DefaultMaxConcurrency < 0 {
		return fmt.Errorf("rate_limit.default_max_concurrency must not be negative")
	}
	if cfg.RateLimit.DefaultTPM > 0 {
		return fmt.Errorf("rate_limit.default_tpm is reserved; TPM enforcement is not implemented")
	}
	if cfg.RateLimit.RedisURL != "" {
		return fmt.Errorf("rate_limit.redis_url is reserved; redis rate limiter backend is not implemented")
	}
	if cfg.Quota.Backend != "" {
		return fmt.Errorf("quota.backend is reserved; quota enforcement is not implemented")
	}
	if cfg.Quota.DSN != "" {
		return fmt.Errorf("quota.dsn is reserved; quota enforcement is not implemented")
	}
	if cfg.Quota.DefaultBudget < 0 {
		return fmt.Errorf("quota.default_budget must not be negative")
	}
	if cfg.Quota.DefaultBudget > 0 {
		return fmt.Errorf("quota.default_budget is reserved; quota enforcement is not implemented")
	}
	if cfg.Quota.Enabled {
		return fmt.Errorf("quota enforcement is not implemented; set quota.enabled=false")
	}
	if cfg.Store.Type != "" || cfg.Store.DSN != "" {
		return fmt.Errorf("store persistence config is reserved; control-plane store is not implemented")
	}
	if cfg.KMS.Mode == "local" && (cfg.KMS.Vault.Address != "" || cfg.KMS.Vault.Path != "" || cfg.KMS.Vault.TokenEnv != "") {
		return fmt.Errorf("kms.vault is reserved; vault KMS backend is not implemented")
	}
	for _, p := range cfg.Providers {
		if !p.Enabled {
			continue
		}
		providerID := p.ID
		if providerID == "" {
			providerID = p.Name
		}
		if p.MaxRPM < 0 {
			return fmt.Errorf("provider %q: max_rpm must not be negative", providerID)
		}
		if p.MaxRPM > 0 {
			return fmt.Errorf("provider %q: max_rpm is reserved; provider RPM enforcement is not implemented", providerID)
		}
		if p.MaxTPM < 0 {
			return fmt.Errorf("provider %q: max_tpm must not be negative", providerID)
		}
		if p.MaxTPM > 0 {
			return fmt.Errorf("provider %q: max_tpm is reserved; TPM enforcement is not implemented", providerID)
		}
	}
	return nil
}

func newKMSProvider(cfg config.KMSConfig) (kms.Provider, error) {
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
		return local.New(cfg.Local.MasterKeyEnv, backend)
	case "vault":
		return nil, fmt.Errorf("vault KMS backend is not implemented")
	default:
		return nil, fmt.Errorf("unsupported KMS mode: %q", cfg.Mode)
	}
}

func loadSecretEnv(envName, label string) ([]byte, error) {
	if envName == "" {
		return nil, fmt.Errorf("%s env var name is empty", label)
	}
	value := os.Getenv(envName)
	if value == "" {
		return nil, fmt.Errorf("%s env var %q is not set", label, envName)
	}
	return []byte(value), nil
}

func loadJWTSigningKeyEnv(envName string) ([]byte, error) {
	key, err := loadSecretEnv(envName, "JWT signing key")
	if err != nil {
		return nil, err
	}
	if len(key) < middleware.MinJWTSigningKeyBytes {
		utils.MemZero(key)
		return nil, fmt.Errorf("JWT signing key env var %q must contain at least %d bytes", envName, middleware.MinJWTSigningKeyBytes)
	}
	return key, nil
}

func providerRuntime(cfg *config.Config) ([]middleware.ProviderChannel, map[string]string, map[string]string, error) {
	channels := make([]middleware.ProviderChannel, 0, len(cfg.Providers))
	poolKeyMapping := make(map[string]string, len(cfg.Providers))
	providerTypes := make(map[string]string, len(cfg.Providers))

	if len(cfg.Egress.AllowedDomains) == 0 {
		return nil, nil, nil, fmt.Errorf("egress.allowed_domains must contain at least one host")
	}

	for _, p := range cfg.Providers {
		if !p.Enabled {
			continue
		}
		if p.ID == "" {
			return nil, nil, nil, fmt.Errorf("enabled provider has empty id")
		}
		if !isSupportedProviderType(p.Type) {
			return nil, nil, nil, fmt.Errorf("provider %q: provider type %q is not implemented", p.ID, p.Type)
		}
		host, err := providerHost(p.BaseURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("provider %q: %w", p.ID, err)
		}
		if !egress.HostAllowed(host, cfg.Egress.AllowedDomains) {
			return nil, nil, nil, fmt.Errorf("provider %q: base_url host %q is not in egress.allowed_domains", p.ID, host)
		}

		channels = append(channels, middleware.ProviderChannel{
			ID:       p.ID,
			Name:     p.Name,
			Type:     p.Type,
			BaseURL:  p.BaseURL,
			KeyID:    p.APIKeyID,
			Models:   p.Models,
			Weight:   p.Weight,
			Priority: p.Priority,
			Enabled:  p.Enabled,
		})
		poolKeyMapping[p.ID] = p.APIKeyID
		providerTypes[p.ID] = p.Type
	}

	if len(channels) == 0 {
		return nil, nil, nil, fmt.Errorf("at least one provider must be enabled")
	}

	return channels, poolKeyMapping, providerTypes, nil
}

func providerHost(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid base_url: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("base_url must use https")
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("base_url must include a host")
	}
	return parsed.Hostname(), nil
}

func isSupportedProviderType(providerType string) bool {
	switch providerType {
	case "openai", "deepseek":
		return true
	default:
		return false
	}
}
