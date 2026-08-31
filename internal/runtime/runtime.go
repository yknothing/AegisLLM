// Package runtime wires configuration into the concrete Aegis runtime.
//
// SECURITY: This package is the composition root. It is responsible for
// preserving the security-critical middleware order and for closing long-lived
// secret material on shutdown.
package runtime

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM/internal/admin"
	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/egress"
	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/kms/factory"
	"github.com/yknothing/AegisLLM/internal/middleware"
	"github.com/yknothing/AegisLLM/internal/proxy"
	"github.com/yknothing/AegisLLM/internal/quota"
	"github.com/yknothing/AegisLLM/internal/revocation"
	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/utils"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
)

// NewServer builds a runnable Aegis server with middleware registered in the
// ADR-004 order.
func NewServer(cfg *config.Config, logger *slog.Logger) (*server.Server, error) {
	return newServer(cfg, logger, nil)
}

func newServer(cfg *config.Config, logger *slog.Logger, proxyRootCAs *x509.CertPool) (*server.Server, error) {
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

	revocationReader, err := revocation.NewReader(
		cfg.Auth.Revocation.FilePath,
		cfg.Auth.Revocation.RefreshInterval,
	)
	if err != nil {
		_ = closeRuntimeResources(signingKey, kmsProvider, nil)
		return nil, fmt.Errorf("loading revocation state: %w", err)
	}

	channels, poolKeyMapping, providerTypes, err := providerRuntime(cfg)
	if err != nil {
		_ = closeRuntimeResources(signingKey, kmsProvider, revocationReader)
		return nil, err
	}
	if err := verifyProviderCredentials(context.Background(), kmsProvider, channels); err != nil {
		_ = closeRuntimeResources(signingKey, kmsProvider, revocationReader)
		return nil, err
	}

	engine := proxy.NewEngine(proxy.StreamConfig{
		MaxRequestBodySize: cfg.Server.MaxRequestBodySize,
		StreamTimeout:      cfg.Server.WriteTimeout,
		AllowedDomains:     cfg.Egress.AllowedDomains,
		RootCAs:            proxyRootCAs,
	})

	quotaManager, err := newQuotaManager(cfg)
	if err != nil {
		_ = closeRuntimeResources(signingKey, kmsProvider, revocationReader)
		return nil, err
	}

	opts, err := runtimeMiddlewareOptions(cfg, signingKey, revocationReader, kmsProvider, channels, poolKeyMapping, providerTypes, engine, quotaManager)
	if err != nil {
		_ = closeRuntimeResources(signingKey, kmsProvider, revocationReader)
		return nil, err
	}

	modelsPipeline, err := newModelsPipeline(cfg, logger, signingKey, revocationReader, channels)
	if err != nil {
		_ = closeRuntimeResources(signingKey, kmsProvider, revocationReader)
		return nil, err
	}
	opts = append(opts, server.WithHandler(
		gatewayconst.HTTPRoute(http.MethodGet, gatewayconst.PathModels),
		http.HandlerFunc(modelsPipeline.ServeHTTP),
	))

	var adminHandler *admin.Handler
	if cfg.Admin.Enabled {
		adminHandler, err = newAdminHandler(cfg, logger, signingKey, kmsProvider, quotaManager, channels)
		if err != nil {
			_ = closeRuntimeResources(signingKey, kmsProvider, revocationReader)
			return nil, err
		}
		adminMux := http.NewServeMux()
		adminHandler.RegisterRoutes(adminMux)
		opts = append(opts, server.WithAdminHandler(adminMux))
		opts = append(opts, server.WithShutdownHook(adminHandler.Close))
	}

	opts = append(opts, server.WithShutdownHook(func() error {
		return closeRuntimeResources(signingKey, kmsProvider, revocationReader)
	}))

	srv, err := server.New(cfg, logger, opts...)
	if err != nil {
		_ = adminHandler.Close()
		_ = closeRuntimeResources(signingKey, kmsProvider, revocationReader)
		return nil, err
	}
	return srv, nil
}

// verifyProviderCredentials fails startup unless every distinct enabled
// provider credential can be decrypted and satisfies the outbound header-value
// contract. It intentionally does not include key IDs or backend errors in the
// returned error because both can contain deployment secrets. Every decrypted
// buffer is zeroed before returning.
func verifyProviderCredentials(ctx context.Context, provider kms.Provider, channels []middleware.ProviderChannel) error {
	seen := make(map[string]struct{}, len(channels))
	for _, channel := range channels {
		if _, ok := seen[channel.KeyID]; ok {
			continue
		}
		seen[channel.KeyID] = struct{}{}

		credential, err := provider.GetKey(ctx, channel.KeyID)
		if err != nil || credential == nil {
			if credential != nil {
				credential.Close()
			}
			return errors.New("provider credential preflight failed")
		}
		credentialErr := utils.ValidateProviderCredentialHeaderValue(credential.Bytes())
		credential.Close()
		if credentialErr != nil {
			return errors.New("provider credential preflight failed")
		}
	}
	return nil
}

type runtimeResourceCloser interface {
	Close() error
}

// closeRuntimeResources removes live signing and provider key material before
// stopping the non-secret revocation poller. All close errors are retained.
func closeRuntimeResources(signingKey []byte, kmsProvider, revocationReader runtimeResourceCloser) error {
	utils.MemZero(signingKey)
	var kmsErr error
	if kmsProvider != nil {
		kmsErr = kmsProvider.Close()
	}
	var revocationErr error
	if revocationReader != nil {
		revocationErr = revocationReader.Close()
	}
	return errors.Join(kmsErr, revocationErr)
}

const (
	runtimeStepAuth         = "auth"
	runtimeStepRateLimit    = "rate_limit"
	runtimeStepQuota        = "quota"
	runtimeStepPIIRedaction = "pii_redaction"
	runtimeStepRouter       = "router"
	runtimeStepKMS          = "kms"
	runtimeStepAdapter      = "adapter"
	runtimeStepProxy        = "proxy"
)

func runtimeMiddlewareOrder(rateLimitEnabled, quotaEnabled bool) []string {
	order := []string{runtimeStepAuth}
	if rateLimitEnabled {
		order = append(order, runtimeStepRateLimit)
	}
	if quotaEnabled {
		order = append(order, runtimeStepQuota)
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
	revocationStore middleware.RevocationStore,
	kmsProvider kms.Provider,
	channels []middleware.ProviderChannel,
	poolKeyMapping map[string]string,
	providerTypes map[string]string,
	engine *proxy.Engine,
	quotaManager *quota.Manager,
) ([]server.Option, error) {
	order := runtimeMiddlewareOrder(cfg.RateLimit.Enabled, cfg.Quota.Enabled)
	opts := make([]server.Option, 0, len(order))
	for _, step := range order {
		switch step {
		case runtimeStepAuth:
			opts = append(opts, server.WithMiddleware(middleware.Auth(middleware.AuthConfig{
				SigningKey: signingKey,
				Issuer:     cfg.Auth.Issuer,
				Expiry:     cfg.Auth.TokenExpiry,
				Revocation: revocationStore,
			})))
		case runtimeStepRateLimit:
			opts = append(opts, server.WithMiddleware(middleware.RateLimiter(middleware.RateLimitConfig{
				Backend:            cfg.RateLimit.Backend,
				RedisURL:           cfg.RateLimit.RedisURL,
				DefaultRPM:         cfg.RateLimit.DefaultRPM,
				DefaultTPM:         cfg.RateLimit.DefaultTPM,
				DefaultMaxConc:     cfg.RateLimit.DefaultMaxConcurrency,
				MaxRequestBodySize: cfg.Server.MaxRequestBodySize,
			})))
		case runtimeStepQuota:
			opts = append(opts, server.WithMiddleware(middleware.Quota(quotaManager)))
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
	if err := config.ValidateServerConfig(cfg.Server); err != nil {
		return err
	}
	if cfg.Auth.TokenExpiry <= 0 {
		return fmt.Errorf("auth.token_expiry must be positive")
	}
	if cfg.Auth.TokenExpiry > virtualkey.MaxTokenTTL {
		return fmt.Errorf("auth.token_expiry must not exceed the maximum supported lifetime")
	}
	if strings.TrimSpace(cfg.Auth.Issuer) == "" {
		return fmt.Errorf("auth.issuer must not be empty")
	}
	if cfg.Auth.Issuer != strings.TrimSpace(cfg.Auth.Issuer) {
		return fmt.Errorf("auth.issuer must not contain leading or trailing whitespace")
	}
	if len(cfg.Auth.Issuer) > virtualkey.MaxRevocableIdentifierBytes {
		return fmt.Errorf("auth.issuer must not exceed %d bytes", virtualkey.MaxRevocableIdentifierBytes)
	}
	if err := config.ValidateRevocationConfig(cfg.Auth.Revocation); err != nil {
		return err
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
	if cfg.RateLimit.DefaultRPM == 0 {
		return fmt.Errorf("rate_limit.default_rpm must be positive")
	}
	if cfg.RateLimit.DefaultTPM < 0 {
		return fmt.Errorf("rate_limit.default_tpm must not be negative")
	}
	if cfg.RateLimit.DefaultMaxConcurrency < 0 {
		return fmt.Errorf("rate_limit.default_max_concurrency must not be negative")
	}
	if cfg.RateLimit.DefaultMaxConcurrency == 0 {
		return fmt.Errorf("rate_limit.default_max_concurrency must be positive")
	}
	if cfg.RateLimit.RedisURL != "" {
		return fmt.Errorf("rate_limit.redis_url is reserved; redis rate limiter backend is not implemented")
	}
	if !cfg.RateLimit.Enabled {
		return fmt.Errorf("rate_limit.enabled must be true for the v0.2.1 runtime")
	}
	if err := validateRuntimeQuota(cfg); err != nil {
		return err
	}
	if cfg.Admin.Enabled {
		host, port, err := net.SplitHostPort(cfg.Admin.Address)
		if err != nil || strings.TrimSpace(port) == "" {
			return fmt.Errorf("admin.address must be host:port")
		}
		if !gatewayconst.IsLoopbackHost(host) {
			return fmt.Errorf("admin.address must bind to a loopback host")
		}
		if strings.TrimSpace(cfg.Admin.TokenEnv) == "" {
			return fmt.Errorf("admin.token_env must not be empty")
		}
		if os.Getenv(cfg.Admin.TokenEnv) == "" {
			return fmt.Errorf("environment variable %q for admin token is not set", cfg.Admin.TokenEnv)
		}
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
	if _, _, _, err := providerRuntime(cfg); err != nil {
		return err
	}
	if cfg.KMS.Mode == "local" && strings.TrimSpace(cfg.KMS.Local.KeyStorePath) == "" {
		return fmt.Errorf("kms.local.key_store_path must not be empty")
	}
	return nil
}

func newKMSProvider(cfg config.KMSConfig) (kms.Provider, error) {
	return factory.New(cfg)
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
	if err := config.ValidateEnabledProviderIDs(cfg.Providers); err != nil {
		return nil, nil, nil, err
	}
	if err := config.ValidateEnabledProviderModels(cfg.Providers); err != nil {
		return nil, nil, nil, err
	}
	channels := make([]middleware.ProviderChannel, 0, len(cfg.Providers))
	poolKeyMapping := make(map[string]string, len(cfg.Providers))
	providerTypes := make(map[string]string, len(cfg.Providers))

	rules, err := egress.ParseAllowlist(cfg.Egress.AllowedDomains)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("egress.allowed_domains: %w", err)
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
		endpoint, err := egress.ParseHTTPSURL(p.BaseURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("provider %q: %w", p.ID, err)
		}
		if !egress.EndpointAllowed(endpoint, rules) {
			return nil, nil, nil, fmt.Errorf("provider %q: base_url endpoint %q is not in egress.allowed_domains", p.ID, endpoint.Host+":"+endpoint.Port)
		}

		channels = append(channels, middleware.ProviderChannel{
			ID:         p.ID,
			Name:       p.Name,
			Type:       p.Type,
			BaseURL:    p.BaseURL,
			KeyID:      p.APIKeyID,
			Models:     p.Models,
			Weight:     p.Weight,
			Priority:   p.Priority,
			APIVersion: p.APIVersion,
			Enabled:    p.Enabled,
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
	endpoint, err := egress.ParseHTTPSURL(rawURL)
	if err != nil {
		return "", err
	}
	return endpoint.Host, nil
}

func isSupportedProviderType(providerType string) bool {
	return gatewayconst.IsSupportedProviderType(providerType)
}

const adminRevocationLockTimeout = 2 * time.Second

func validateRuntimeQuota(cfg *config.Config) error {
	switch cfg.Quota.Backend {
	case "", gatewayconst.QuotaBackendMemory:
	default:
		return fmt.Errorf("quota.backend is reserved; only memory is implemented")
	}
	if cfg.Quota.DSN != "" {
		return fmt.Errorf("quota.dsn is reserved; durable quota backends are not implemented")
	}
	if cfg.Quota.DefaultBudget < 0 {
		return fmt.Errorf("quota.default_budget must not be negative")
	}
	if !cfg.Quota.Enabled {
		if cfg.Quota.Backend != "" {
			return fmt.Errorf("quota.backend requires quota.enabled=true")
		}
		if cfg.Quota.DefaultBudget > 0 {
			return fmt.Errorf("quota.default_budget requires quota.enabled=true")
		}
		return nil
	}
	return validateQuotaPricing(cfg)
}

func validateQuotaPricing(cfg *config.Config) error {
	table := overlayPricingTable(cfg)
	models := enabledProviderModels(cfg)
	if err := table.RequireModels(models); err != nil {
		return errors.New("quota model pricing is incomplete")
	}
	return nil
}

func overlayPricingTable(cfg *config.Config) *quota.PricingTable {
	table := quota.NewPricingTable()
	applyQuotaPrices(table, cfg)
	return table
}

func applyQuotaPrices(table *quota.PricingTable, cfg *config.Config) {
	for _, price := range cfg.Quota.ModelPrices {
		table.Set(quota.ModelPricing{
			Model:            price.Model,
			InputPerMillion:  price.InputPerMillion,
			OutputPerMillion: price.OutputPerMillion,
		})
	}
}

func enabledProviderModels(cfg *config.Config) []string {
	models := make([]string, 0)
	for _, provider := range cfg.Providers {
		if !provider.Enabled {
			continue
		}
		models = append(models, provider.Models...)
	}
	return models
}

func newQuotaManager(cfg *config.Config) (*quota.Manager, error) {
	if !cfg.Quota.Enabled {
		return nil, nil
	}
	manager := quota.NewManager(quota.NewMemoryStore(), cfg.Quota.DefaultBudget)
	applyQuotaPrices(manager.Pricing(), cfg)
	if err := manager.Pricing().RequireModels(enabledProviderModels(cfg)); err != nil {
		return nil, errors.New("quota model pricing is incomplete")
	}
	return manager, nil
}

// newModelsPipeline builds the authenticated GET /v1/models catalog handler.
func newModelsPipeline(
	cfg *config.Config,
	logger *slog.Logger,
	signingKey []byte,
	revocationStore middleware.RevocationStore,
	channels []middleware.ProviderChannel,
) (*server.Pipeline, error) {
	pipeline, err := server.NewPipeline(cfg, logger)
	if err != nil {
		return nil, err
	}
	pipeline.Use(middleware.Auth(middleware.AuthConfig{
		SigningKey: signingKey,
		Issuer:     cfg.Auth.Issuer,
		Expiry:     cfg.Auth.TokenExpiry,
		Revocation: revocationStore,
	}))
	pipeline.Use(middleware.ModelsList(channels))
	return pipeline, nil
}

func newAdminHandler(
	cfg *config.Config,
	logger *slog.Logger,
	signingKey []byte,
	kmsProvider kms.Provider,
	quotaManager *quota.Manager,
	channels []middleware.ProviderChannel,
) (*admin.Handler, error) {
	token, err := loadSecretEnv(cfg.Admin.TokenEnv, "admin token")
	if err != nil {
		return nil, err
	}
	if len(token) < gatewayconst.MinAdminTokenBytes {
		utils.MemZero(token)
		return nil, fmt.Errorf("admin token env var %q must contain at least %d bytes", cfg.Admin.TokenEnv, gatewayconst.MinAdminTokenBytes)
	}
	signingCopy := append([]byte(nil), signingKey...)
	services := admin.Services{
		SigningKey:    signingCopy,
		Issuer:        cfg.Auth.Issuer,
		MaxTTL:        cfg.Auth.TokenExpiry,
		AllowedModels: enabledProviderModels(cfg),
		Revoker:       revocation.NewWriter(cfg.Auth.Revocation.FilePath, adminRevocationLockTimeout),
	}
	if quotaManager != nil {
		services.Quota = quotaManager
	}
	return admin.NewHandlerWithServices(kmsProvider, logger, token, services), nil
}
