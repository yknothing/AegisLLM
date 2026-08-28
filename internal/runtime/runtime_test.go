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
	"sync/atomic"
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

	var upstreamCalls atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
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
	cfg.Egress.AllowedDomains = []string{upstream.Listener.Addr().String()}
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
	requestBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"email me at alice\u0040example.com"}]}`
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
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want one successful request", got)
	}

	modelsReq, err := http.NewRequest(http.MethodGet, gatewayURL+"/v1/models", nil)
	if err != nil {
		t.Fatalf("build models request: %v", err)
	}
	modelsReq.Header.Set("Authorization", "Bearer "+token)
	modelsResp, err := client.Do(modelsReq)
	if err != nil {
		t.Fatalf("models request: %v", err)
	}
	modelsBody, modelsReadErr := io.ReadAll(modelsResp.Body)
	_ = modelsResp.Body.Close()
	if modelsReadErr != nil {
		t.Fatalf("read models response: %v", modelsReadErr)
	}
	if modelsResp.StatusCode != http.StatusOK {
		t.Fatalf("models status = %d body=%s, want 200", modelsResp.StatusCode, modelsBody)
	}
	var modelsPayload struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(modelsBody, &modelsPayload); err != nil {
		t.Fatalf("decode models: %v", err)
	}
	if modelsPayload.Object != "list" || len(modelsPayload.Data) != 1 || modelsPayload.Data[0].ID != "gpt-4o-mini" {
		t.Fatalf("models payload = %+v, want gpt-4o-mini", modelsPayload)
	}

	unauthModels, err := http.NewRequest(http.MethodGet, gatewayURL+"/v1/models", nil)
	if err != nil {
		t.Fatalf("build unauthenticated models request: %v", err)
	}
	unauthResp, err := client.Do(unauthModels)
	if err != nil {
		t.Fatalf("unauthenticated models request: %v", err)
	}
	_, _ = io.Copy(io.Discard, unauthResp.Body)
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated models status = %d, want 401", unauthResp.StatusCode)
	}

	// A duplicate model member must be rejected before routing or proxying.
	// The gateway authorizes the decoded model, while an upstream parser could
	// otherwise choose a different occurrence from the forwarded bytes.
	ambiguousBodies := []string{
		`{"model":"forbidden-model","model":"gpt-4o-mini","messages":[]}`,
		`{"model":"forbidden-model","Model":"gpt-4o-mini","messages":[]}`,
		`{"model":"gpt-4o-mini","messages":[],"user\u0040example.com":"safe"}`,
		`{"model":"gpt-4o-mini","messages":[],"phone":5551234567}`,
	}
	for _, ambiguousBody := range ambiguousBodies {
		ambiguousRequest, err := http.NewRequest(
			http.MethodPost,
			gatewayURL+"/v1/chat/completions",
			strings.NewReader(ambiguousBody),
		)
		if err != nil {
			t.Fatalf("build ambiguous request: %v", err)
		}
		ambiguousRequest.Header.Set("Authorization", "Bearer "+token)
		ambiguousRequest.Header.Set("Content-Type", "application/json")
		ambiguousResponse, err := client.Do(ambiguousRequest)
		if err != nil {
			t.Fatalf("ambiguous gateway request: %v", err)
		}
		_, _ = io.Copy(io.Discard, ambiguousResponse.Body)
		_ = ambiguousResponse.Body.Close()
		if ambiguousResponse.StatusCode != http.StatusBadRequest {
			t.Fatalf("ambiguous request status = %d, want %d", ambiguousResponse.StatusCode, http.StatusBadRequest)
		}
		if got := upstreamCalls.Load(); got != 1 {
			t.Fatalf("ambiguous request reached upstream; calls = %d, want 1", got)
		}
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
	cfg.KMS.Local.KeyStorePath = filepath.Join(t.TempDir(), "keys")
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

func TestNewServerRejectsUnavailableProviderCredentialsAtStartup(t *testing.T) {
	tests := []struct {
		name    string
		corrupt bool
	}{
		{name: "missing"},
		{name: "corrupt", corrupt: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := initializedRuntimeConfig(t)
			const keyIDCanary = "CANARY-provider-key-id-7f642a"
			cfg.Providers[0].APIKeyID = keyIDCanary

			if tt.corrupt {
				seedStore, err := newKMSProvider(cfg.KMS)
				if err != nil {
					t.Fatalf("open seed KMS: %v", err)
				}
				if err := seedStore.StoreKey(context.Background(), keyIDCanary, []byte("provider-secret")); err != nil {
					_ = seedStore.Close()
					t.Fatalf("seed provider key: %v", err)
				}
				if err := seedStore.Close(); err != nil {
					t.Fatalf("close seed KMS: %v", err)
				}

				entries, err := os.ReadDir(cfg.KMS.Local.KeyStorePath)
				if err != nil {
					t.Fatalf("read key store: %v", err)
				}
				if len(entries) != 1 {
					t.Fatalf("key store entries = %d, want 1", len(entries))
				}
				blobPath := filepath.Join(cfg.KMS.Local.KeyStorePath, entries[0].Name())
				if err := os.WriteFile(blobPath, []byte("corrupt encrypted blob"), 0o600); err != nil {
					t.Fatalf("corrupt provider key blob: %v", err)
				}
			}

			_, err := NewServer(cfg, nil)
			if err == nil || !strings.Contains(err.Error(), "provider credential preflight failed") {
				t.Fatalf("NewServer error = %v, want provider credential preflight rejection", err)
			}
			if strings.Contains(err.Error(), keyIDCanary) {
				t.Fatalf("NewServer error leaked provider key ID: %v", err)
			}
		})
	}
}

func TestNewServerRejectsUnsafeProviderCredentialsAtStartup(t *testing.T) {
	tests := []struct {
		name       string
		credential []byte
	}{
		{name: "embedded newline", credential: []byte("sk-first\nsk-second")},
		{name: "embedded carriage return", credential: []byte("sk-first\rsk-second")},
		{name: "NUL", credential: []byte{'s', 'k', 0, 'x'}},
		{name: "control", credential: []byte{'s', 'k', 0x1f, 'x'}},
		{name: "DEL", credential: []byte{'s', 'k', 0x7f, 'x'}},
		{name: "non ASCII", credential: []byte("sk-密钥")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := initializedRuntimeConfig(t)
			seedStore, err := newKMSProvider(cfg.KMS)
			if err != nil {
				t.Fatalf("open seed KMS: %v", err)
			}
			plaintext := append([]byte(nil), tt.credential...)
			secret := string(plaintext)
			if err := seedStore.StoreKey(context.Background(), cfg.Providers[0].APIKeyID, plaintext); err != nil {
				_ = seedStore.Close()
				t.Fatalf("seed provider key: %v", err)
			}
			if err := seedStore.Close(); err != nil {
				t.Fatalf("close seed KMS: %v", err)
			}

			_, err = NewServer(cfg, nil)
			if err == nil || !strings.Contains(err.Error(), "provider credential preflight failed") {
				t.Fatalf("NewServer error = %v, want provider credential preflight rejection", err)
			}
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Fatal("NewServer reflected the rejected provider credential")
			}
		})
	}
}

func initializedRuntimeConfig(t *testing.T) *config.Config {
	t.Helper()

	const (
		masterKeyEnv = "TEST_AEGIS_STARTUP_MASTER_KEY"
		jwtKeyEnv    = "TEST_AEGIS_STARTUP_JWT_KEY"
	)
	t.Setenv(masterKeyEnv, hex.EncodeToString(make([]byte, 32)))
	t.Setenv(jwtKeyEnv, "0123456789abcdef0123456789abcdef")

	cfg := minimalRuntimeConfig()
	cfg.KMS.Local.MasterKeyEnv = masterKeyEnv
	cfg.KMS.Local.KeyStorePath = filepath.Join(t.TempDir(), "keys")
	cfg.Auth.JWTSigningKeyEnv = jwtKeyEnv
	cfg.Auth.Revocation.FilePath = filepath.Join(t.TempDir(), "revocations.json")
	if _, err := revocation.NewWriter(cfg.Auth.Revocation.FilePath, 2*time.Second).Init(context.Background(), time.Now()); err != nil {
		t.Fatalf("initialize revocation state: %v", err)
	}
	return cfg
}

func TestCloseRuntimeResourcesZerosSecretsAndClosesKMSFirst(t *testing.T) {
	signingKey := []byte("runtime-signing-secret")
	order := make([]string, 0, 2)
	signingKeyWasZeroed := false

	kmsCloser := runtimeTestCloser(func() error {
		signingKeyWasZeroed = true
		for _, b := range signingKey {
			if b != 0 {
				signingKeyWasZeroed = false
				break
			}
		}
		order = append(order, "kms")
		return nil
	})
	revocationCloser := runtimeTestCloser(func() error {
		order = append(order, "revocation")
		return nil
	})

	if err := closeRuntimeResources(signingKey, kmsCloser, revocationCloser); err != nil {
		t.Fatalf("closeRuntimeResources returned error: %v", err)
	}
	if !signingKeyWasZeroed {
		t.Fatal("KMS close ran before the signing key was zeroed")
	}
	if got, want := strings.Join(order, ","), "kms,revocation"; got != want {
		t.Fatalf("close order = %q, want %q", got, want)
	}
}

type runtimeTestCloser func() error

func (close runtimeTestCloser) Close() error {
	return close()
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

func TestProviderRuntimeRejectsUnroutableEnabledProviderModelsWithoutLeakingMetadata(t *testing.T) {
	const (
		providerCanary = "provider-model-contract-canary-5f81"
		modelCanary    = "model-contract-canary-40c3"
	)
	tests := []struct {
		name       string
		models     []string
		disableAll bool
	}{
		{name: "no enabled provider", disableAll: true},
		{name: "enabled provider has no models", models: []string{}},
		{name: "enabled provider has empty model", models: []string{""}},
		{name: "enabled provider has whitespace-only model", models: []string{" \t "}},
		{name: "enabled provider model is not trim-stable", models: []string{" " + modelCanary + " "}},
		{name: "enabled provider has duplicate model", models: []string{modelCanary, modelCanary}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := minimalRuntimeConfig()
			if tt.disableAll {
				cfg.Providers[0].ID = providerCanary
				cfg.Providers[0].Enabled = false
			} else {
				invalid := cfg.Providers[0]
				invalid.ID = providerCanary
				invalid.Name = "Provider Model Contract Canary"
				invalid.APIKeyID = "provider-model-contract-key"
				invalid.Models = tt.models
				cfg.Providers = append(cfg.Providers, invalid)
			}

			_, _, _, err := providerRuntime(cfg)
			if err == nil {
				t.Fatal("providerRuntime accepted an enabled-provider model contract violation")
			}
			if strings.Contains(err.Error(), providerCanary) || strings.Contains(err.Error(), modelCanary) {
				t.Fatalf("providerRuntime error leaked provider or model metadata: %v", err)
			}
		})
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

func TestProviderRuntimeRejectsUnsafeProviderURLMetadata(t *testing.T) {
	tests := []string{
		"https://user:password@api.openai.com",
		"https://api.openai.com#unexpected",
	}
	for _, baseURL := range tests {
		t.Run(baseURL, func(t *testing.T) {
			cfg := minimalRuntimeConfig()
			cfg.Providers[0].BaseURL = baseURL
			if _, _, _, err := providerRuntime(cfg); err == nil {
				t.Fatalf("providerRuntime accepted unsafe base_url %q", baseURL)
			}
		})
	}
}

func TestProviderRuntimeRequiresExactNonDefaultPort(t *testing.T) {
	cfg := minimalRuntimeConfig()
	cfg.Providers[0].BaseURL = "https://api.openai.com:8443"
	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime let a host-only rule authorize a non-default port")
	}

	cfg.Egress.AllowedDomains = []string{"api.openai.com:8443"}
	if _, _, _, err := providerRuntime(cfg); err != nil {
		t.Fatalf("providerRuntime rejected exact non-default port: %v", err)
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
				Type:     "bedrock",
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
		name      string
		mutate    func(*config.Config)
		wantErr   string
		forbidden string
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
			name: "auth issuer above revocation bound",
			mutate: func(cfg *config.Config) {
				cfg.Auth.Issuer = strings.Repeat("i", 1025)
			},
			wantErr: "auth.issuer must not exceed 1024 bytes",
		},
		{
			name: "auth issuer with surrounding whitespace",
			mutate: func(cfg *config.Config) {
				cfg.Auth.Issuer = " aegis "
			},
			wantErr: "auth.issuer must not contain leading or trailing whitespace",
		},
		{
			name: "token expiry above safe retention bound",
			mutate: func(cfg *config.Config) {
				cfg.Auth.TokenExpiry = time.Duration(1<<63 - 1)
			},
			wantErr: "auth.token_expiry must not exceed the maximum supported lifetime",
		},
		{
			name: "malformed provider URL does not leak userinfo",
			mutate: func(cfg *config.Config) {
				cfg.Providers[0].BaseURL = "https://user:CANARY-runtime-url-secret-5e2d91@api.openai.com/%zz"
			},
			wantErr:   "invalid target URL",
			forbidden: "CANARY-runtime-url-secret-5e2d91",
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
			wantErr: "quota.default_budget requires quota.enabled=true",
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
			name:    "missing durable local KMS path",
			mutate:  func(*config.Config) {},
			wantErr: "kms.local.key_store_path must not be empty",
		},
		{
			name: "disabled rate limit",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.Enabled = false
			},
			wantErr: "rate_limit.enabled must be true",
		},
		{
			name: "zero default RPM",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.DefaultRPM = 0
			},
			wantErr: "rate_limit.default_rpm must be positive",
		},
		{
			name: "zero default concurrency",
			mutate: func(cfg *config.Config) {
				cfg.RateLimit.DefaultMaxConcurrency = 0
			},
			wantErr: "rate_limit.default_max_concurrency must be positive",
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
			if tt.forbidden != "" && strings.Contains(err.Error(), tt.forbidden) {
				t.Fatalf("NewServer error leaked forbidden value %q: %v", tt.forbidden, err)
			}
		})
	}
}

func TestRuntimeMiddlewareOrder(t *testing.T) {
	tests := []struct {
		name             string
		rateLimitEnabled bool
		quotaEnabled     bool
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
		{
			name:             "with quota",
			rateLimitEnabled: true,
			quotaEnabled:     true,
			want: []string{
				runtimeStepAuth,
				runtimeStepRateLimit,
				runtimeStepQuota,
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
			if got := runtimeMiddlewareOrder(tt.rateLimitEnabled, tt.quotaEnabled); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("runtimeMiddlewareOrder(%t, %t) = %v, want %v", tt.rateLimitEnabled, tt.quotaEnabled, got, tt.want)
			}
		})
	}
}

func TestRuntimeAcceptsQuotaAndTPM(t *testing.T) {
	cfg := minimalRuntimeConfig()
	cfg.KMS.Local.KeyStorePath = t.TempDir()
	cfg.Quota.Enabled = true
	cfg.RateLimit.DefaultTPM = 4000
	if err := validateRuntimeConfig(cfg); err != nil {
		t.Fatalf("validateRuntimeConfig rejected implemented quota/TPM: %v", err)
	}
}

func TestRuntimeRejectsQuotaWithoutPricing(t *testing.T) {
	cfg := minimalRuntimeConfig()
	cfg.Quota.Enabled = true
	cfg.Providers[0].Models = []string{"unpriced-custom-model"}
	if err := validateRuntimeConfig(cfg); err == nil || !strings.Contains(err.Error(), "quota model pricing is incomplete") {
		t.Fatalf("validateRuntimeConfig error = %v, want incomplete pricing", err)
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
