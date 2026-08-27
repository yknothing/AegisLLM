// Package config handles loading and validating the Aegis gateway configuration.
//
// SECURITY NOTE: This package NEVER stores or logs plaintext API keys.
// Provider credentials are referenced by KMS key IDs, not raw values.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM/internal/egress"
	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
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

const (
	maxConfigFileBytes int64 = 1 << 20
	// DefaultMaxRequestBodySize is the standalone runtime request-body limit.
	// It matches the semantic PII processing envelope used by every data-plane
	// request, so a validated configuration never advertises a wider limit than
	// the mandatory policy pipeline can accept.
	DefaultMaxRequestBodySize int64 = 4 << 20
	// MaxRequestBodySizeLimit is the largest accepted configured body limit.
	MaxRequestBodySizeLimit int64 = 4 << 20
)

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
	MasterKeyEnv           string `json:"master_key_env"`           // Name of env var holding the master key
	KeyStorePath           string `json:"key_store_path"`           // Directory for encrypted local key blobs
	MinimumEnvelopeVersion int    `json:"minimum_envelope_version"` // 1 during legacy migration; 2 after completion
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
	MaxRPM   int      `json:"max_rpm"` // Reserved until provider-level RPM enforcement exists
	MaxTPM   int      `json:"max_tpm"` // Reserved until TPM enforcement exists
	Enabled  bool     `json:"enabled"`
	Priority int      `json:"priority"` // Lower = higher priority for fallback
}

// AuthConfig defines authentication settings.
type AuthConfig struct {
	JWTSigningKeyEnv string           `json:"jwt_signing_key_env"` // Env var for JWT private key
	TokenExpiry      time.Duration    `json:"token_expiry"`        // Maximum accepted token lifetime
	Issuer           string           `json:"issuer"`
	Revocation       RevocationConfig `json:"revocation"`
}

// RevocationConfig defines the durable single-host virtual-key revocation
// reader. Shared/distributed backends remain a future control-plane concern.
type RevocationConfig struct {
	Backend         string        `json:"backend"`
	FilePath        string        `json:"file_path"`
	RefreshInterval time.Duration `json:"refresh_interval"`
}

const maxRevocationRefreshInterval = 5 * time.Second

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
// quota.enabled=true and configured quota storage/budget fields fail fast until
// runtime enforcement exists. JSON config files reject those fields by presence.
type QuotaConfig struct {
	Enabled       bool    `json:"enabled"`
	Backend       string  `json:"backend"` // Reserved durable store backend
	DSN           string  `json:"dsn"`
	DefaultBudget float64 `json:"default_budget"` // Reserved default monthly budget in USD
}

// StoreConfig reserves the persistence layer for future control-plane state.
// JSON config files reject this object by presence because no runtime store is
// wired yet.
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
	if err := unmarshalStrict(data, &raw); err != nil {
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
		JWTSigningKeyEnv *string           `json:"jwt_signing_key_env"`
		TokenExpiry      json.RawMessage   `json:"token_expiry"`
		Issuer           *string           `json:"issuer"`
		Revocation       *RevocationConfig `json:"revocation"`
	}

	var raw authConfigJSON
	if err := unmarshalStrict(data, &raw); err != nil {
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
	if raw.Revocation != nil {
		c.Revocation = *raw.Revocation
	}

	return nil
}

// UnmarshalJSON accepts a human-readable refresh interval while rejecting
// unknown revocation fields.
func (c *RevocationConfig) UnmarshalJSON(data []byte) error {
	type revocationConfigJSON struct {
		Backend         *string         `json:"backend"`
		FilePath        *string         `json:"file_path"`
		RefreshInterval json.RawMessage `json:"refresh_interval"`
	}

	var raw revocationConfigJSON
	if err := unmarshalStrict(data, &raw); err != nil {
		return err
	}
	if raw.Backend != nil {
		c.Backend = *raw.Backend
	}
	if raw.FilePath != nil {
		c.FilePath = *raw.FilePath
	}
	if raw.RefreshInterval != nil {
		d, err := parseDuration(raw.RefreshInterval, "auth.revocation.refresh_interval")
		if err != nil {
			return err
		}
		c.RefreshInterval = d
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
			return 0, fmt.Errorf("%s must be a valid duration", field)
		}
		return d, nil
	}

	var nanos int64
	if err := json.Unmarshal(raw, &nanos); err == nil {
		return time.Duration(nanos), nil
	}

	return 0, fmt.Errorf("%s must be a duration string or integer nanoseconds", field)
}

func unmarshalStrict(data []byte, dst any) error {
	if err := validateJSONMembers(data, reflect.TypeOf(dst)); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return errors.New("json: unknown field in configuration")
		}
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validateJSONMembers(data []byte, dstType reflect.Type) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return scanJSONValue(decoder, dstType)
}

func scanJSONValue(decoder *json.Decoder, expectedType reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("invalid JSON configuration")
	}
	if token == nil {
		if expectedType != nil {
			return errors.New("json: null is not allowed in configuration")
		}
		return nil
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		return scanJSONObject(decoder, expectedType)
	case '[':
		return scanJSONArray(decoder, expectedType)
	default:
		return errors.New("invalid JSON configuration")
	}
}

func scanJSONObject(decoder *json.Decoder, expectedType reflect.Type) error {
	exactFields, requireExactFields := exactJSONFields(expectedType)
	mapValueType := jsonMapValueType(expectedType)
	seenExact := make(map[string]struct{})
	seenFolded := make(map[string]string)
	hasUnknownField := false

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("invalid JSON configuration")
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("invalid JSON configuration")
		}

		if _, exists := seenExact[name]; exists {
			return errors.New("json: duplicate object member in configuration")
		}
		seenExact[name] = struct{}{}

		folded := asciiFoldJSONMember(name)
		if previous, exists := seenFolded[folded]; exists && previous != name {
			return errors.New("json: ambiguous object member in configuration")
		}
		seenFolded[folded] = name

		valueType := mapValueType
		if requireExactFields {
			var exists bool
			valueType, exists = exactFields[name]
			if !exists {
				hasUnknownField = true
				valueType = nil
			}
		}
		if err := scanJSONValue(decoder, valueType); err != nil {
			return err
		}
	}

	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("invalid JSON configuration")
	}
	if hasUnknownField {
		return errors.New("json: unknown field in configuration")
	}
	return nil
}

func scanJSONArray(decoder *json.Decoder, expectedType reflect.Type) error {
	elementType := jsonElementType(expectedType)
	for decoder.More() {
		if err := scanJSONValue(decoder, elementType); err != nil {
			return err
		}
	}

	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return errors.New("invalid JSON configuration")
	}
	return nil
}

func exactJSONFields(valueType reflect.Type) (map[string]reflect.Type, bool) {
	valueType = indirectJSONType(valueType)
	if valueType == nil || valueType.Kind() != reflect.Struct {
		return nil, false
	}

	fields := make(map[string]reflect.Type)
	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		if !field.IsExported() {
			continue
		}

		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields, true
}

func jsonMapValueType(valueType reflect.Type) reflect.Type {
	valueType = indirectJSONType(valueType)
	if valueType != nil && valueType.Kind() == reflect.Map {
		return valueType.Elem()
	}
	return nil
}

func jsonElementType(valueType reflect.Type) reflect.Type {
	valueType = indirectJSONType(valueType)
	if valueType != nil && (valueType.Kind() == reflect.Array || valueType.Kind() == reflect.Slice) {
		return valueType.Elem()
	}
	return nil
}

func indirectJSONType(valueType reflect.Type) reflect.Type {
	for valueType != nil && valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	return valueType
}

func asciiFoldJSONMember(name string) string {
	folded := []byte(name)
	for i, char := range folded {
		if char >= 'A' && char <= 'Z' {
			folded[i] = char + ('a' - 'A')
		}
	}
	return string(folded)
}

func rejectReservedConfigFields(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}

	if rateLimitRaw, ok := root["rate_limit"]; ok && !isJSONNull(rateLimitRaw) {
		var rateLimitFields map[string]json.RawMessage
		if err := json.Unmarshal(rateLimitRaw, &rateLimitFields); err != nil {
			return fmt.Errorf("rate_limit must be an object: %w", err)
		}
		if _, exists := rateLimitFields["redis_url"]; exists {
			return errors.New("rate_limit.redis_url is reserved; redis rate limiter backend is not implemented")
		}
	}
	if quotaRaw, ok := root["quota"]; ok && !isJSONNull(quotaRaw) {
		var quotaFields map[string]json.RawMessage
		if err := json.Unmarshal(quotaRaw, &quotaFields); err != nil {
			return fmt.Errorf("quota must be an object: %w", err)
		}
		for _, field := range []string{"backend", "dsn", "default_budget"} {
			if _, exists := quotaFields[field]; exists {
				return fmt.Errorf("quota.%s is reserved; quota enforcement is not implemented", field)
			}
		}
	}
	if kmsRaw, ok := root["kms"]; ok && !isJSONNull(kmsRaw) {
		var kmsFields map[string]json.RawMessage
		if err := json.Unmarshal(kmsRaw, &kmsFields); err != nil {
			return fmt.Errorf("kms must be an object: %w", err)
		}
		if _, exists := kmsFields["vault"]; exists {
			return errors.New("kms.vault is reserved; vault KMS backend is not implemented")
		}
	}
	if _, exists := root["store"]; exists {
		return errors.New("store persistence config is reserved; control-plane store is not implemented")
	}

	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// Load reads and validates the configuration from the given path.
// If path is empty, it attempts to load from default locations.
func Load(path string) (*Config, error) {
	return load(path, true)
}

// LoadForOperator loads and structurally validates configuration without
// requiring unrelated secret environment variables. Individual operator
// commands load only the secret material they actually need.
func LoadForOperator(path string) (*Config, error) {
	return load(path, false)
}

func load(path string, requireSecretEnv bool) (*Config, error) {
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
		data, err := readBoundedConfigFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := unmarshalStrict(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
		if err := rejectReservedConfigFields(data); err != nil {
			return nil, fmt.Errorf("config validation: %w", err)
		}
		bindLegacyLoopbackAllowlistPorts(cfg)
	}

	if err := cfg.validate(requireSecretEnv); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// bindLegacyLoopbackAllowlistPorts preserves the existing configuration
// contract for local provider fixtures without restoring host-wide port
// authorization. A bare loopback IP is expanded only to the exact HTTPS ports
// declared by enabled providers on that same address. Bare non-loopback IPs and
// unmatched loopback entries remain invalid and fail the strict egress gate.
func bindLegacyLoopbackAllowlistPorts(cfg *Config) {
	if cfg == nil {
		return
	}

	bound := make([]string, 0, len(cfg.Egress.AllowedDomains))
	seen := make(map[string]struct{}, len(cfg.Egress.AllowedDomains))
	appendUnique := func(entry string) {
		if _, exists := seen[entry]; exists {
			return
		}
		seen[entry] = struct{}{}
		bound = append(bound, entry)
	}

	for _, entry := range cfg.Egress.AllowedDomains {
		address, err := netip.ParseAddr(entry)
		if err != nil || address.Zone() != "" || !address.IsLoopback() {
			appendUnique(entry)
			continue
		}
		address = address.Unmap()

		matched := false
		for _, provider := range cfg.Providers {
			if !provider.Enabled {
				continue
			}
			endpoint, err := egress.ParseHTTPSURL(provider.BaseURL)
			if err != nil || !endpoint.IPLiteral || !endpoint.IP.IsLoopback() || endpoint.IP.Unmap() != address {
				continue
			}
			appendUnique(net.JoinHostPort(endpoint.IP.String(), endpoint.Port))
			matched = true
		}
		if !matched {
			appendUnique(entry)
		}
	}

	cfg.Egress.AllowedDomains = bound
}

func readBoundedConfigFile(path string) ([]byte, error) {
	file, err := openConfigNoFollow(path)
	if err != nil {
		return nil, errors.New("unable to open config file")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("config input must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("config input permissions %o allow group/other writes", info.Mode().Perm())
	}
	if info.Size() < 0 || info.Size() > maxConfigFileBytes {
		return nil, fmt.Errorf("config input exceeds %d-byte size limit", maxConfigFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return nil, errors.New("unable to read config file")
	}
	if int64(len(data)) > maxConfigFileBytes {
		return nil, fmt.Errorf("config input exceeds %d-byte size limit", maxConfigFileBytes)
	}
	return data, nil
}

// defaultConfig returns a sensible default configuration for standalone mode.
func defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Address:            ":8080",
			ReadTimeout:        30 * time.Second,
			WriteTimeout:       120 * time.Second, // Long timeout for streaming
			ShutdownTimeout:    15 * time.Second,
			MaxRequestBodySize: DefaultMaxRequestBodySize,
		},
		KMS: KMSConfig{
			Mode: "local",
			Local: LocalKMS{
				MasterKeyEnv:           "AEGIS_MASTER_KEY",
				MinimumEnvelopeVersion: 2,
			},
		},
		Auth: AuthConfig{
			JWTSigningKeyEnv: "AEGIS_JWT_KEY",
			TokenExpiry:      24 * time.Hour,
			Issuer:           "aegis",
			Revocation: RevocationConfig{
				Backend:         "file",
				FilePath:        "aegis.revocations.json",
				RefreshInterval: 500 * time.Millisecond,
			},
		},
		RateLimit: RateLimitConfig{
			Enabled:               true,
			Backend:               "memory",
			DefaultRPM:            60,
			DefaultTPM:            0,
			DefaultMaxConcurrency: 10,
		},
		Quota: QuotaConfig{
			Enabled: false,
		},
	}
}

// ValidateServerConfig checks server runtime bounds and TLS settings.
func ValidateServerConfig(server ServerConfig) error {
	if server.Address == "" {
		return errors.New("server address must not be empty")
	}
	if server.ReadTimeout <= 0 {
		return errors.New("server.read_timeout must be positive")
	}
	if server.WriteTimeout <= 0 {
		return errors.New("server.write_timeout must be positive")
	}
	if server.ShutdownTimeout <= 0 {
		return errors.New("server.shutdown_timeout must be positive")
	}
	if server.MaxRequestBodySize <= 0 {
		return errors.New("server.max_request_body_size must be positive")
	}
	if server.MaxRequestBodySize > MaxRequestBodySizeLimit {
		return fmt.Errorf("server.max_request_body_size must not exceed %d", MaxRequestBodySizeLimit)
	}
	if server.TLS.Enabled {
		if server.TLS.CertFile == "" || server.TLS.KeyFile == "" {
			return errors.New("server TLS requires cert_file and key_file")
		}
		switch server.TLS.MinVersion {
		case "", "1.3", "TLS1.3", "tls1.3":
		default:
			return errors.New("server.tls.min_version currently supports only TLS 1.3")
		}
	}
	return nil
}

// validate checks the configuration for logical errors and security issues.
func (c *Config) validate(requireSecretEnv bool) error {
	if err := ValidateServerConfig(c.Server); err != nil {
		return err
	}
	if c.Auth.TokenExpiry <= 0 {
		return errors.New("auth.token_expiry must be positive")
	}
	if c.Auth.TokenExpiry > virtualkey.MaxTokenTTL {
		return errors.New("auth.token_expiry must not exceed the maximum supported lifetime")
	}
	if strings.TrimSpace(c.Auth.Issuer) == "" {
		return errors.New("auth.issuer must not be empty")
	}
	if c.Auth.Issuer != strings.TrimSpace(c.Auth.Issuer) {
		return errors.New("auth.issuer must not contain leading or trailing whitespace")
	}
	if len(c.Auth.Issuer) > virtualkey.MaxRevocableIdentifierBytes {
		return fmt.Errorf("auth.issuer must not exceed %d bytes", virtualkey.MaxRevocableIdentifierBytes)
	}
	if err := ValidateRevocationConfig(c.Auth.Revocation); err != nil {
		return err
	}

	if err := ValidateEnabledProviderIDs(c.Providers); err != nil {
		return err
	}
	if err := ValidateEnabledProviderModels(c.Providers); err != nil {
		return err
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
		if len(p.APIKeyID) > kms.MaxKeyIDBytes {
			return fmt.Errorf("provider %q: api_key_id must not exceed %d bytes", providerName, kms.MaxKeyIDBytes)
		}
		if p.MaxRPM < 0 {
			return fmt.Errorf("provider %q: max_rpm must not be negative", providerName)
		}
		if p.MaxRPM > 0 {
			return fmt.Errorf("provider %q: max_rpm is reserved; provider RPM enforcement is not implemented", providerName)
		}
		if p.MaxTPM < 0 {
			return fmt.Errorf("provider %q: max_tpm must not be negative", providerName)
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
	if err := egress.ValidateAllowlist(c.Egress.AllowedDomains); err != nil {
		return fmt.Errorf("egress.allowed_domains: %w", err)
	}

	switch c.RateLimit.Backend {
	case "memory":
	case "redis":
		return errors.New("redis rate limiter backend is not implemented")
	default:
		return fmt.Errorf("unsupported rate_limit backend: %q", c.RateLimit.Backend)
	}
	if c.RateLimit.DefaultRPM < 0 {
		return errors.New("rate_limit.default_rpm must not be negative")
	}
	if c.RateLimit.DefaultRPM == 0 {
		return errors.New("rate_limit.default_rpm must be positive")
	}
	if c.RateLimit.DefaultTPM < 0 {
		return errors.New("rate_limit.default_tpm must not be negative")
	}
	if c.RateLimit.DefaultMaxConcurrency < 0 {
		return errors.New("rate_limit.default_max_concurrency must not be negative")
	}
	if c.RateLimit.DefaultMaxConcurrency == 0 {
		return errors.New("rate_limit.default_max_concurrency must be positive")
	}
	if c.RateLimit.DefaultTPM > 0 {
		return errors.New("rate_limit.default_tpm is reserved; TPM enforcement is not implemented")
	}
	if c.RateLimit.RedisURL != "" {
		return errors.New("rate_limit.redis_url is reserved; redis rate limiter backend is not implemented")
	}
	if !c.RateLimit.Enabled {
		return errors.New("rate_limit.enabled must be true for the v0.2.1 runtime")
	}

	if c.Quota.Backend != "" {
		return errors.New("quota.backend is reserved; quota enforcement is not implemented")
	}
	if c.Quota.DSN != "" {
		return errors.New("quota.dsn is reserved; quota enforcement is not implemented")
	}
	if c.Quota.DefaultBudget < 0 {
		return errors.New("quota.default_budget must not be negative")
	}
	if c.Quota.DefaultBudget > 0 {
		return errors.New("quota.default_budget is reserved; quota enforcement is not implemented")
	}
	if c.Quota.Enabled {
		return errors.New("quota enforcement is not implemented; set quota.enabled=false")
	}
	if c.Store.Type != "" || c.Store.DSN != "" {
		return errors.New("store persistence config is reserved; control-plane store is not implemented")
	}

	switch c.KMS.Mode {
	case "local":
		if c.KMS.Vault.Address != "" || c.KMS.Vault.Path != "" || c.KMS.Vault.TokenEnv != "" {
			return errors.New("kms.vault is reserved; vault KMS backend is not implemented")
		}
		if c.KMS.Local.MasterKeyEnv == "" {
			return errors.New("local KMS requires master_key_env to be set")
		}
		if strings.TrimSpace(c.KMS.Local.KeyStorePath) == "" {
			return errors.New("kms.local.key_store_path must not be empty")
		}
		if c.KMS.Local.MinimumEnvelopeVersion != 1 && c.KMS.Local.MinimumEnvelopeVersion != 2 {
			return errors.New("kms.local.minimum_envelope_version must be 1 or 2")
		}
		// Verify the env var exists (but never log its value)
		if requireSecretEnv && os.Getenv(c.KMS.Local.MasterKeyEnv) == "" {
			return fmt.Errorf("environment variable %q for master key is not set", c.KMS.Local.MasterKeyEnv)
		}
	case "vault":
		return errors.New("vault KMS backend is not implemented")
	default:
		return fmt.Errorf("unsupported KMS mode: %q", c.KMS.Mode)
	}

	return nil
}

// ValidateEnabledProviderIDs prevents route-to-credential ambiguity by
// requiring every enabled provider ID to be non-empty and unique.
func ValidateEnabledProviderIDs(providers []Provider) error {
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if !provider.Enabled {
			continue
		}
		if strings.TrimSpace(provider.ID) == "" {
			return errors.New("enabled provider id must not be empty")
		}
		if _, exists := seen[provider.ID]; exists {
			return fmt.Errorf("enabled provider id %q is duplicated", provider.ID)
		}
		seen[provider.ID] = struct{}{}
	}
	return nil
}

// ValidateEnabledProviderModels prevents healthy-but-unroutable runtimes by
// requiring every enabled provider to declare a canonical, unique model set.
// Errors intentionally omit provider and model values because configuration
// metadata may be deployment-sensitive.
func ValidateEnabledProviderModels(providers []Provider) error {
	for _, provider := range providers {
		if !provider.Enabled {
			continue
		}
		if len(provider.Models) == 0 {
			return errors.New("enabled provider must configure at least one model")
		}

		seen := make(map[string]struct{}, len(provider.Models))
		for _, model := range provider.Models {
			trimmed := strings.TrimSpace(model)
			if trimmed == "" {
				return errors.New("enabled provider model must not be empty")
			}
			if trimmed != model {
				return errors.New("enabled provider model must not contain leading or trailing whitespace")
			}
			if _, exists := seen[model]; exists {
				return errors.New("enabled provider models must not contain duplicates")
			}
			seen[model] = struct{}{}
		}
	}
	return nil
}

// ValidateRevocationConfig validates the standalone durable revocation reader.
func ValidateRevocationConfig(cfg RevocationConfig) error {
	if cfg.Backend != "file" {
		return fmt.Errorf("unsupported auth.revocation backend: %q", cfg.Backend)
	}
	if strings.TrimSpace(cfg.FilePath) == "" {
		return errors.New("auth.revocation.file_path must not be empty")
	}
	if cfg.RefreshInterval <= 0 {
		return errors.New("auth.revocation.refresh_interval must be positive")
	}
	if cfg.RefreshInterval > maxRevocationRefreshInterval {
		return fmt.Errorf("auth.revocation.refresh_interval must not exceed %s", maxRevocationRefreshInterval)
	}
	return nil
}
