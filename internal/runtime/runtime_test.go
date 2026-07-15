package runtime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/middleware"
	"github.com/yknothing/AegisLLM/internal/requestid"
	"github.com/yknothing/AegisLLM/internal/revocation"
)

func TestRuntimeHermeticTLSProviderSuccessPath(t *testing.T) {
	const (
		masterKeyEnv = "TEST_AEGIS_E2E_MASTER_KEY"
		jwtKeyEnv    = "TEST_AEGIS_E2E_JWT_KEY"
		providerKey  = "provider-secret"
	)

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("upstream request = %s %s, want POST /v1/chat/completions", r.Method, r.URL.Path)
		}
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("upstream TLS version = %v, want TLS 1.3", r.TLS)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+providerKey {
			t.Errorf("upstream authorization = %q, want provider credential", got)
		}
		if got := r.Header.Get("X-Api-Key"); got != "" {
			t.Errorf("client credential reached upstream: %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		bodyText := string(body)
		if strings.Contains(bodyText, "alice@example.com") || !strings.Contains(bodyText, "[EMAIL_REDACTED]") {
			t.Errorf("upstream body was not redacted: %q", bodyText)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(requestid.Header, "provider-request-e2e")
		w.Header().Set("Set-Cookie", "provider-session=secret")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"chatcmpl-e2e","choices":[]}`)
	}))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	t.Setenv(masterKeyEnv, hex.EncodeToString(masterKey))
	jwtKey := []byte("runtime-e2e-signing-key-32-bytes-minimum")
	t.Setenv(jwtKeyEnv, string(jwtKey))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve gateway address: %v", err)
	}
	gatewayAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release gateway address: %v", err)
	}

	cfg := minimalRuntimeConfig()
	cfg.Server.Address = gatewayAddress
	cfg.KMS.Local.MasterKeyEnv = masterKeyEnv
	cfg.KMS.Local.KeyStorePath = filepath.Join(t.TempDir(), "keys")
	cfg.Auth.JWTSigningKeyEnv = jwtKeyEnv
	cfg.Auth.Revocation.FilePath = filepath.Join(t.TempDir(), "revocations.json")
	cfg.Providers[0].BaseURL = upstream.URL
	cfg.Egress.AllowedDomains = []string{"127.0.0.1"}
	if _, err := revocation.NewWriter(cfg.Auth.Revocation.FilePath, 2*time.Second).Init(context.Background(), time.Now()); err != nil {
		t.Fatalf("initialize revocation state: %v", err)
	}

	seedStore, err := newKMSProvider(cfg.KMS)
	if err != nil {
		t.Fatalf("open seed KMS: %v", err)
	}
	if err := seedStore.StoreKey(context.Background(), cfg.Providers[0].APIKeyID, []byte(providerKey)); err != nil {
		_ = seedStore.Close()
		t.Fatalf("seed provider key: %v", err)
	}
	if err := seedStore.Close(); err != nil {
		t.Fatalf("close seed KMS: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	srv, err := newServer(cfg, nil, roots)
	if err != nil {
		t.Fatalf("build runtime server: %v", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	serverStopped := false
	defer func() {
		if serverStopped {
			return
		}
		cancel()
		<-runErr
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	gatewayURL := "http://" + gatewayAddress
	for attempt := 0; ; attempt++ {
		resp, requestErr := client.Get(gatewayURL + "/health")
		if requestErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if attempt == 99 {
			t.Fatalf("gateway did not become healthy: %v", requestErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	now := time.Now()
	token := signRuntimeTestToken(t, jwtKey, middleware.VirtualKeyClaims{
		KeyID:          "virtual-key-e2e",
		Subject:        "operator-e2e",
		Models:         []string{"gpt-4o-mini"},
		MaxRPM:         10,
		MaxConcurrency: 2,
		KeySource:      middleware.KeySourcePool,
		IssuedAt:       now.Add(-time.Minute).Unix(),
		ExpiresAt:      now.Add(time.Hour).Unix(),
		Issuer:         "aegis",
	})
	requestBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"email me at alice@example.com"}]}`
	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/v1/chat/completions", strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build gateway request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "client-secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	responseBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read gateway response: %v", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gateway status = %d body=%s, want 200", resp.StatusCode, responseBody)
	}
	if got := resp.Header.Get("X-Upstream-Request-Id"); got != "provider-request-e2e" {
		t.Fatalf("upstream request id = %q, want provider-request-e2e", got)
	}
	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("unsafe upstream cookie reached client: %q", got)
	}
	if got, want := string(responseBody), `{"id":"chatcmpl-e2e","choices":[]}`; got != want {
		t.Fatalf("response body = %q, want %q", got, want)
	}

	if _, err := revocation.NewWriter(cfg.Auth.Revocation.FilePath, 2*time.Second).Revoke(
		context.Background(), cfg.Auth.Issuer, "virtual-key-e2e", time.Now(), cfg.Auth.TokenExpiry,
	); err != nil {
		t.Fatalf("revoke virtual key during runtime: %v", err)
	}
	revocationDeadline := time.Now().Add(cfg.Auth.Revocation.RefreshInterval + 250*time.Millisecond)
	for {
		revokedRequest, err := http.NewRequest(
			http.MethodPost,
			gatewayURL+"/v1/chat/completions",
			strings.NewReader(requestBody),
		)
		if err != nil {
			t.Fatalf("build revoked gateway request: %v", err)
		}
		revokedRequest.Header.Set("Authorization", "Bearer "+token)
		revokedRequest.Header.Set("Content-Type", "application/json")
		revokedResponse, requestErr := client.Do(revokedRequest)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, revokedResponse.Body)
			_ = revokedResponse.Body.Close()
			if revokedResponse.StatusCode == http.StatusUnauthorized {
				break
			}
		}
		if time.Now().After(revocationDeadline) {
			t.Fatalf("revoked token was not rejected within refresh SLA: last error=%v", requestErr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	shutdownErr := <-runErr
	serverStopped = true
	if shutdownErr != nil {
		t.Fatalf("runtime shutdown: %v", shutdownErr)
	}
}

func TestNewServerRejectsMissingRevocationSnapshot(t *testing.T) {
	const (
		masterKeyEnv = "TEST_AEGIS_MISSING_REVOCATION_MASTER"
		jwtKeyEnv    = "TEST_AEGIS_MISSING_REVOCATION_JWT"
	)
	t.Setenv(masterKeyEnv, hex.EncodeToString(make([]byte, 32)))
	t.Setenv(jwtKeyEnv, "0123456789abcdef0123456789abcdef")

	cfg := minimalRuntimeConfig()
	cfg.KMS.Local.MasterKeyEnv = masterKeyEnv
	cfg.Auth.JWTSigningKeyEnv = jwtKeyEnv
	cfg.Auth.Revocation = config.RevocationConfig{
		Backend:         "file",
		FilePath:        filepath.Join(t.TempDir(), "missing.json"),
		RefreshInterval: 500 * time.Millisecond,
	}

	if _, err := NewServer(cfg, nil); err == nil || !strings.Contains(err.Error(), "revocation") {
		t.Fatalf("NewServer missing revocation error = %v, want startup rejection", err)
	}
}

func signRuntimeTestToken(t *testing.T, key []byte, claims middleware.VirtualKeyClaims) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal token header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal token claims: %v", err)
	}
	segments := []string{
		base64.RawURLEncoding.EncodeToString(headerJSON),
		base64.RawURLEncoding.EncodeToString(claimsJSON),
	}
	signingInput := strings.Join(segments, ".")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	segments = append(segments, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return strings.Join(segments, ".")
}

func TestProviderRuntimeAcceptsExplicitEgressDomains(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Name:     "OpenAI Primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}

	channels, keyMapping, providerTypes, err := providerRuntime(cfg)
	if err != nil {
		t.Fatalf("providerRuntime returned error: %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("channels len = %d, want 1", len(channels))
	}
	if keyMapping["openai-primary"] != "openai-key-1" {
		t.Fatalf("key mapping was not populated")
	}
	if providerTypes["openai-primary"] != "openai" {
		t.Fatalf("provider type was not populated")
	}
}

func TestExampleConfigEgressMatchesEnabledRuntimeProviders(t *testing.T) {
	t.Setenv("AEGIS_MASTER_KEY", hex.EncodeToString(make([]byte, 32)))

	cfg, err := config.Load(filepath.Join("..", "..", "aegis.example.json"))
	if err != nil {
		t.Fatalf("Load example config returned error: %v", err)
	}
	if _, _, _, err := providerRuntime(cfg); err != nil {
		t.Fatalf("providerRuntime rejected example config: %v", err)
	}

	enabledHosts := make(map[string]struct{})
	for _, provider := range cfg.Providers {
		if !provider.Enabled {
			t.Fatalf("example provider %q is disabled; keep future providers out of the current runtime example", provider.ID)
		}
		if !isSupportedProviderType(provider.Type) {
			t.Fatalf("example provider %q type %q is not supported by v0.2.1 runtime", provider.ID, provider.Type)
		}
		host, err := providerHost(provider.BaseURL)
		if err != nil {
			t.Fatalf("example provider %q base_url rejected: %v", provider.ID, err)
		}
		enabledHosts[host] = struct{}{}
	}

	allowedHosts := make(map[string]struct{})
	for _, host := range cfg.Egress.AllowedDomains {
		allowedHosts[host] = struct{}{}
	}
	if !reflect.DeepEqual(allowedHosts, enabledHosts) {
		t.Fatalf("example egress allowlist = %#v, want enabled provider hosts %#v", allowedHosts, enabledHosts)
	}
}

func TestProviderRuntimeRejectsDuplicateEnabledProviderIDs(t *testing.T) {
	cfg := minimalRuntimeConfig()
	duplicate := cfg.Providers[0]
	duplicate.APIKeyID = "other-key"
	cfg.Providers = append(cfg.Providers, duplicate)
	if _, _, _, err := providerRuntime(cfg); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("providerRuntime duplicate ID error = %v", err)
	}
}

func TestProviderRuntimeRejectsHTTPProvider(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "unsafe",
				Type:     "openai",
				BaseURL:  "http://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted a non-HTTPS provider")
	}
}

func TestProviderRuntimeRejectsImplicitEgressSubdomain(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Type:     "openai",
				BaseURL:  "https://tenant.api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted an implicit egress subdomain")
	}
}

func TestProviderRuntimeAllowsExplicitEgressWildcardSubdomain(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"*.openai.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err != nil {
		t.Fatalf("providerRuntime rejected explicit wildcard subdomain: %v", err)
	}
}

func TestProviderRuntimeRequiresExplicitEgressAllowlist(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted an empty egress allowlist")
	}
}

func TestProviderRuntimeRejectsUnsupportedProviderType(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "anthropic-primary",
				Type:     "anthropic",
				BaseURL:  "https://api.anthropic.com",
				APIKeyID: "anthropic-key-1",
				Models:   []string{"claude-sonnet-4-20250514"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.anthropic.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted an unsupported provider type")
	}
}

func TestNewKMSProviderUsesFileBackend(t *testing.T) {
	masterKeyHex := hex.EncodeToString(make([]byte, 32))
	const envVar = "TEST_AEGIS_RUNTIME_FILE_KMS_KEY"
	t.Setenv(envVar, masterKeyHex)

	dir := filepath.Join(t.TempDir(), "keys")
	provider, err := newKMSProvider(config.KMSConfig{
		Mode: "local",
		Local: config.LocalKMS{
			MasterKeyEnv: envVar,
			KeyStorePath: dir,
		},
	})
	if err != nil {
		t.Fatalf("newKMSProvider returned error: %v", err)
	}
	defer func() {
		_ = provider.Close()
	}()

	if err := provider.StoreKey(context.Background(), "openai-key-1", []byte("sk-runtime-file-key")); err != nil {
		t.Fatalf("StoreKey returned error: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("file count = %d, want 1", len(entries))
	}
}

func TestLoadJWTSigningKeyEnvRejectsWeakSecret(t *testing.T) {
	const envVar = "TEST_AEGIS_WEAK_JWT_KEY"
	t.Setenv(envVar, "short-secret")

	key, err := loadJWTSigningKeyEnv(envVar)
	if err == nil {
		t.Fatal("loadJWTSigningKeyEnv accepted a weak JWT signing key")
	}
	if key != nil {
		t.Fatal("loadJWTSigningKeyEnv returned key bytes on failure")
	}
	if strings.Contains(err.Error(), "short-secret") {
		t.Fatalf("error leaked JWT signing key value: %v", err)
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("error = %v, want minimum length failure", err)
	}
}

func TestLoadJWTSigningKeyEnvAcceptsStrongSecret(t *testing.T) {
	const envVar = "TEST_AEGIS_STRONG_JWT_KEY"
	secret := "0123456789abcdef0123456789abcdef"
	t.Setenv(envVar, secret)

	key, err := loadJWTSigningKeyEnv(envVar)
	if err != nil {
		t.Fatalf("loadJWTSigningKeyEnv returned error: %v", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	if string(key) != secret {
		t.Fatalf("key bytes = %q, want configured secret", string(key))
	}
}

func TestNewServerRejectsUnsupportedRuntimeControls(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name: "token expiry",
			mutate: func(cfg *config.Config) {
				cfg.Auth.TokenExpiry = 0
			},
			wantErr: "auth.token_expiry must be positive",
		},
		{
			name: "empty auth issuer",
			mutate: func(cfg *config.Config) {
				cfg.Auth.Issuer = ""
			},
			wantErr: "auth.issuer must not be empty",
		},
		{
			name: "zero read timeout",
			mutate: func(cfg *config.Config) {
				cfg.Server.ReadTimeout = 0
			},
			wantErr: "server.read_timeout must be positive",
		},
		{
			name: "negative read timeout",
			mutate: func(cfg *config.Config) {
				cfg.Server.ReadTimeout = -1
			},
			wantErr: "server.read_timeout must be positive",
		},
		{
			name: "zero write timeout",
			mutate: func(cfg *config.Config) {
				cfg.Server.WriteTimeout = 0
			},
			wantErr: "server.write_timeout must be positive",
		},
		{
			name: "negative write timeout",
			mutate: func(cfg *config.Config) {
				cfg.Server.WriteTimeout = -1
			},
			wantErr: "server.write_timeout must be positive",
		},
		{
			name: "zero shutdown timeout",
			mutate: func(cfg *config.Config) {
				cfg.Server.ShutdownTimeout = 0
			},
			wantErr: "server.shutdown_timeout must be positive",
		},
		{
			name: "negative shutdown timeout",
			mutate: func(cfg *config.Config) {
				cfg.Server.ShutdownTimeout = -1
			},
			wantErr: "server.shutdown_timeout must be positive",
		},
		{
			name: "zero max request body size",
			mutate: func(cfg *config.Config) {
				cfg.Server.MaxRequestBodySize = 0
			},
			wantErr: "server.max_request_body_size must be positive",
		},
		{
			name: "negative max request body size",
			mutate: func(cfg *config.Config) {
				cfg.Server.MaxRequestBodySize = -1
			},
			wantErr: "server.max_request_body_size must be positive",
		},
		{
			name: "max request body size above maximum",
			mutate: func(cfg *config.Config) {
				cfg.Server.MaxRequestBodySize = config.MaxRequestBodySizeLimit + 1
			},
			wantErr: "server.max_request_body_size must not exceed",
		},
		{
			name: "quota",
			mutate: func(cfg *config.Config) {
				cfg.Quota.Enabled = true
			},
			wantErr: "quota enforcement is not implemented",
		},
		{
			name: "quota backend",
			mutate: func(cfg *config.Config) {
				cfg.Quota.Backend = "sqlite"
			},
			wantErr: "quota.backend is reserved",
		},
		{
			name: "quota dsn",
			mutate: func(cfg *config.Config) {
				cfg.Quota.DSN = "aegis.db"
			},
			wantErr: "quota.dsn is reserved",
		},
		{
			name: "quota default budget",
			mutate: func(cfg *config.Config) {
				cfg.Quota.DefaultBudget = 100.0
			},
			wantErr: "quota.default_budget is reserved",
		},
		{
			name: "negative quota default budget",
			mutate: func(cfg *config.Config) {
				cfg.Quota.DefaultBudget = -1.0
			},
			wantErr: "quota.default_budget must not be negative",
		},
		{
			name: "store type",
			mutate: func(cfg *config.Config) {
				cfg.Store.Type = "sqlite"
			},
			wantErr: "store persistence config is reserved",
		},
		{
			name: "store dsn",
			mutate: func(cfg *config.Config) {
				cfg.Store.DSN = "aegis.db"
			},
			wantErr: "store persistence config is reserved",
		},
		{
			name: "vault config",
			mutate: func(cfg *config.Config) {
				cfg.KMS.Vault.Address = "https://vault.internal:8200"
			},
			wantErr: "kms.vault is reserved",
		},
		{
			name: "unknown rate limit backend",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "memcached"
			},
			wantErr: `unsupported rate_limit backend: "memcached"`,
		},
		{
			name: "disabled redis rate limit backend",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "redis"
			},
			wantErr: "redis rate limiter backend is not implemented",
		},
		{
			name: "disabled default TPM",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "memory"
				cfg.RateLimit.DefaultTPM = 1000
			},
			wantErr: "TPM enforcement is not implemented",
		},
		{
			name: "redis url",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Backend = "memory"
				cfg.RateLimit.RedisURL = "redis://localhost:6379/0"
			},
			wantErr: "rate_limit.redis_url is reserved",
		},
		{
			name: "disabled negative default RPM",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
				cfg.RateLimit.Backend = "memory"
				cfg.RateLimit.DefaultRPM = -1
			},
			wantErr: "rate_limit.default_rpm must not be negative",
		},
		{
			name: "provider RPM",
			mutate: func(cfg *config.Config) {
				cfg.Providers[0].MaxRPM = 100
			},
			wantErr: "provider RPM enforcement is not implemented",
		},
		{
			name: "provider TPM",
			mutate: func(cfg *config.Config) {
				cfg.Providers[0].MaxTPM = 1000
			},
			wantErr: "TPM enforcement is not implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := minimalRuntimeConfig()
			tt.mutate(cfg)

			_, err := NewServer(cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewServer error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestRuntimeMiddlewareOrder(t *testing.T) {
	tests := []struct {
		name             string
		rateLimitEnabled bool
		want             []string
	}{
		{
			name:             "with rate limit",
			rateLimitEnabled: true,
			want: []string{
				runtimeStepAuth,
				runtimeStepRateLimit,
				runtimeStepPIIRedaction,
				runtimeStepRouter,
				runtimeStepKMS,
				runtimeStepAdapter,
				runtimeStepProxy,
			},
		},
		{
			name:             "without rate limit",
			rateLimitEnabled: false,
			want: []string{
				runtimeStepAuth,
				runtimeStepPIIRedaction,
				runtimeStepRouter,
				runtimeStepKMS,
				runtimeStepAdapter,
				runtimeStepProxy,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runtimeMiddlewareOrder(tt.rateLimitEnabled); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("runtimeMiddlewareOrder(%t) = %v, want %v", tt.rateLimitEnabled, got, tt.want)
			}
		})
	}
}

func minimalRuntimeConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Address:            ":0",
			ReadTimeout:        30 * time.Second,
			WriteTimeout:       120 * time.Second,
			ShutdownTimeout:    15 * time.Second,
			MaxRequestBodySize: config.DefaultMaxRequestBodySize,
		},
		KMS: config.KMSConfig{
			Mode: "local",
			Local: config.LocalKMS{
				MasterKeyEnv: "TEST_AEGIS_RUNTIME_MASTER_KEY",
			},
		},
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Name:     "OpenAI Primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		RateLimit: config.RateLimitConfig{
			Enabled:               true,
			Backend:               "memory",
			DefaultRPM:            60,
			DefaultMaxConcurrency: 10,
		},
		Quota: config.QuotaConfig{
			Enabled: false,
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
		Auth: config.AuthConfig{
			TokenExpiry: 24 * time.Hour,
			Issuer:      "aegis",
			Revocation: config.RevocationConfig{
				Backend:         "file",
				FilePath:        filepath.Join(os.TempDir(), "aegis-runtime-test-revocations.json"),
				RefreshInterval: 500 * time.Millisecond,
			},
		},
	}
}
