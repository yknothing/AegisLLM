package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/middleware"
	"github.com/yknothing/AegisLLM/internal/revocation"
)

const (
	liftMasterKeyEnv           = "TEST_AEGIS_LIFT_MASTER_KEY"
	liftJWTKeyEnv              = "TEST_AEGIS_LIFT_JWT_KEY"
	liftAdminTokenEnv          = "TEST_AEGIS_LIFT_ADMIN_TOKEN"
	liftAdminTokenValue        = "0123456789abcdef0123456789abcdef"
	liftJWTSigningKey          = "runtime-e2e-signing-key-32-bytes-minimum"
	liftChatModel              = "gpt-4o-mini"
	liftPrimaryProviderID      = "openai-primary"
	liftFallbackProviderID     = "openai-fallback"
	liftPrimaryKeyID           = "openai-key-1"
	liftFallbackKeyID          = "openai-key-2"
	liftPrimarySecret          = "primary-secret"
	liftFallbackSecret         = "fallback-secret"
	liftPrimaryPriority        = 1
	liftFallbackPriority       = 2
	liftOKJSON                 = `{"id":"chatcmpl-lift","choices":[]}`
	liftChatJSON               = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	liftStreamJSON             = `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	liftSSEDeltaLine           = `data: {"id":"chunk-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hi"}}]}`
	liftSSEDoneLine            = `data: [DONE]`
	liftAdminHealthPath        = "/admin/health"
	liftAdminIssuePath         = "/admin/keys/virtual"
	liftAdminUsagePathPrefix   = "/admin/usage/"
	liftAdminTokenHeader       = "X-Admin-Token"
	liftAdminIssueJSON         = `{"subject":"lift-client","models":["gpt-4o-mini"],"ttl":"1h"}`
	liftUsageProbeKeyID        = "vk_missing"
	liftHealthAttempts         = 100
	liftHealthRetry            = 10 * time.Millisecond
	liftClientTimeout          = 5 * time.Second
	liftOverheadDefaultRPM     = 100_000
	liftOverheadMaxConcurrency = 100
	liftOverheadWarmup         = 20
	liftOverheadSamples        = 200
	liftPercentileP50          = 50
	liftPercentileP95          = 95
	liftPercentileP99          = 99
	liftPercentileMax          = 100
	liftEventStreamType        = "text/event-stream"
)

type liftProvider struct {
	id       string
	keyID    string
	secret   string
	priority int
	handler  http.HandlerFunc
}

type liftRuntimeOptions struct {
	adminEnabled   bool
	defaultRPM     int
	maxConcurrency int
	providers      []liftProvider
}

type liftRuntime struct {
	client     *http.Client
	gatewayURL string
	adminURL   string
	mockURL    string
	jwtKey     []byte
	cancel     context.CancelFunc
	runErr     <-chan error
}

// stop cancels the runtime and waits for Run to return.
func (g *liftRuntime) stop(t *testing.T) {
	t.Helper()
	g.cancel()
	if err := <-g.runErr; err != nil {
		t.Fatalf("runtime shutdown: %v", err)
	}
}

func TestRuntimeInRequestFailover(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	env := startLiftRuntime(t, liftRuntimeOptions{
		providers: []liftProvider{
			{
				id:       liftPrimaryProviderID,
				keyID:    liftPrimaryKeyID,
				secret:   liftPrimarySecret,
				priority: liftPrimaryPriority,
				handler: func(w http.ResponseWriter, r *http.Request) {
					primaryCalls.Add(1)
					w.Header().Set("Content-Type", gatewayconst.JSONContentType)
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = io.WriteString(w, `{"error":{"message":"primary unavailable"}}`)
				},
			},
			{
				id:       liftFallbackProviderID,
				keyID:    liftFallbackKeyID,
				secret:   liftFallbackSecret,
				priority: liftFallbackPriority,
				handler: func(w http.ResponseWriter, r *http.Request) {
					fallbackCalls.Add(1)
					w.Header().Set("Content-Type", gatewayconst.JSONContentType)
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, liftOKJSON)
				},
			},
		},
	})
	defer env.stop(t)

	resp, body := liftChat(t, env, liftChatJSON)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failover status = %d body=%s, want 200", resp.StatusCode, body)
	}
	if string(body) != liftOKJSON {
		t.Fatalf("failover body = %q, want fallback JSON", body)
	}
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("upstream calls primary=%d fallback=%d, want 1 and 1", primaryCalls.Load(), fallbackCalls.Load())
	}
}

func TestRuntimeChatSSE(t *testing.T) {
	var upstreamCalls atomic.Int32
	env := startLiftRuntime(t, liftRuntimeOptions{
		providers: []liftProvider{{
			id:       liftPrimaryProviderID,
			keyID:    liftPrimaryKeyID,
			secret:   liftPrimarySecret,
			priority: liftPrimaryPriority,
			handler: func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.Header().Set("Content-Type", liftEventStreamType)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, liftSSEDeltaLine+"\n\n"+liftSSEDoneLine+"\n\n")
			},
		}},
	})
	defer env.stop(t)

	resp, body := liftChat(t, env, liftStreamJSON)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sse status = %d body=%s, want 200", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), liftEventStreamType) {
		t.Fatalf("sse content-type = %q, want %s", resp.Header.Get("Content-Type"), liftEventStreamType)
	}
	if !strings.Contains(string(body), "data:") || !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("sse body = %q, want data events and [DONE]", body)
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("sse upstream calls = %d, want 1", upstreamCalls.Load())
	}
}

func TestRuntimeAdminLoopbackIssueAndUsage(t *testing.T) {
	env := startLiftRuntime(t, liftRuntimeOptions{
		adminEnabled: true,
		providers: []liftProvider{{
			id:       liftPrimaryProviderID,
			keyID:    liftPrimaryKeyID,
			secret:   liftPrimarySecret,
			priority: liftPrimaryPriority,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", gatewayconst.JSONContentType)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, liftOKJSON)
			},
		}},
	})
	defer env.stop(t)

	unauth, err := http.NewRequest(http.MethodGet, env.adminURL+liftAdminHealthPath, nil)
	if err != nil {
		t.Fatalf("build unauthenticated admin health: %v", err)
	}
	unauthResp, err := env.client.Do(unauth)
	if err != nil {
		t.Fatalf("unauthenticated admin health: %v", err)
	}
	_, _ = io.Copy(io.Discard, unauthResp.Body)
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin status = %d, want 401", unauthResp.StatusCode)
	}

	issueReq, err := http.NewRequest(http.MethodPost, env.adminURL+liftAdminIssuePath, strings.NewReader(liftAdminIssueJSON))
	if err != nil {
		t.Fatalf("build admin issue: %v", err)
	}
	issueReq.Header.Set(liftAdminTokenHeader, liftAdminTokenValue)
	issueReq.Header.Set("Content-Type", gatewayconst.JSONContentType)
	issueResp, err := env.client.Do(issueReq)
	if err != nil {
		t.Fatalf("admin issue: %v", err)
	}
	issueBody, readErr := io.ReadAll(issueResp.Body)
	_ = issueResp.Body.Close()
	if readErr != nil {
		t.Fatalf("read admin issue: %v", readErr)
	}
	if issueResp.StatusCode != http.StatusOK {
		t.Fatalf("admin issue status = %d body=%s, want 200", issueResp.StatusCode, issueBody)
	}
	var issued struct {
		VirtualKey string `json:"virtual_key"`
	}
	if err := json.Unmarshal(issueBody, &issued); err != nil {
		t.Fatalf("decode issued key: %v", err)
	}
	if issued.VirtualKey == "" {
		t.Fatal("admin issue returned an empty virtual key")
	}

	modelsReq, err := http.NewRequest(http.MethodGet, env.gatewayURL+gatewayconst.PathModels, nil)
	if err != nil {
		t.Fatalf("build models with issued key: %v", err)
	}
	modelsReq.Header.Set("Authorization", "Bearer "+issued.VirtualKey)
	modelsResp, err := env.client.Do(modelsReq)
	if err != nil {
		t.Fatalf("models with issued key: %v", err)
	}
	modelsBody, modelsReadErr := io.ReadAll(modelsResp.Body)
	_ = modelsResp.Body.Close()
	if modelsReadErr != nil {
		t.Fatalf("read issued-key models: %v", modelsReadErr)
	}
	if modelsResp.StatusCode != http.StatusNotFound {
		t.Fatalf("issued-key models status = %d body=%s, want 404", modelsResp.StatusCode, modelsBody)
	}

	usageReq, err := http.NewRequest(http.MethodGet, env.adminURL+liftAdminUsagePathPrefix+liftUsageProbeKeyID, nil)
	if err != nil {
		t.Fatalf("build admin usage: %v", err)
	}
	usageReq.Header.Set(liftAdminTokenHeader, liftAdminTokenValue)
	usageResp, err := env.client.Do(usageReq)
	if err != nil {
		t.Fatalf("admin usage: %v", err)
	}
	_, _ = io.Copy(io.Discard, usageResp.Body)
	_ = usageResp.Body.Close()
	if usageResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("usage with quota disabled status = %d, want 503", usageResp.StatusCode)
	}
}

func TestRuntimeGatewayOverheadAgainstMock(t *testing.T) {
	env := startLiftRuntime(t, liftRuntimeOptions{
		defaultRPM:     liftOverheadDefaultRPM,
		maxConcurrency: liftOverheadMaxConcurrency,
		providers: []liftProvider{{
			id:       liftPrimaryProviderID,
			keyID:    liftPrimaryKeyID,
			secret:   liftPrimarySecret,
			priority: liftPrimaryPriority,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", gatewayconst.JSONContentType)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, liftOKJSON)
			},
		}},
	})
	defer env.stop(t)

	token := env.token(t, liftOverheadDefaultRPM, liftOverheadMaxConcurrency)
	for i := 0; i < liftOverheadWarmup; i++ {
		resp, body := liftChatWithToken(t, env, token, liftChatJSON)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("warmup status = %d body=%s, want 200", resp.StatusCode, body)
		}
	}

	samples := make([]time.Duration, 0, liftOverheadSamples)
	for i := 0; i < liftOverheadSamples; i++ {
		started := time.Now()
		resp, body := liftChatWithToken(t, env, token, liftChatJSON)
		elapsed := time.Since(started)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("overhead sample status = %d body=%s, want 200", resp.StatusCode, body)
		}
		samples = append(samples, elapsed)
	}

	p50 := durationPercentile(samples, liftPercentileP50)
	p95 := durationPercentile(samples, liftPercentileP95)
	p99 := durationPercentile(samples, liftPercentileP99)
	t.Logf(
		"aegis_mock_overhead collected_at=%s n=%d success=1.0 p50=%s p95=%s p99=%s",
		time.Now().UTC().Format(time.RFC3339),
		liftOverheadSamples,
		p50,
		p95,
		p99,
	)
}

// startLiftRuntime boots a hermetic TLS mock-upstream gateway for AegisLift e2e checks.
func startLiftRuntime(t *testing.T, opts liftRuntimeOptions) *liftRuntime {
	t.Helper()
	if len(opts.providers) == 0 {
		t.Fatal("startLiftRuntime requires at least one provider")
	}

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	t.Setenv(liftMasterKeyEnv, hex.EncodeToString(masterKey))
	t.Setenv(liftJWTKeyEnv, liftJWTSigningKey)
	if opts.adminEnabled {
		if len(liftAdminTokenValue) < gatewayconst.MinAdminTokenBytes {
			t.Fatalf("admin token length = %d, want >= %d", len(liftAdminTokenValue), gatewayconst.MinAdminTokenBytes)
		}
		t.Setenv(liftAdminTokenEnv, liftAdminTokenValue)
	}

	roots := x509.NewCertPool()
	cfg := minimalRuntimeConfig()
	cfg.Server.Address = reserveLoopbackAddr(t)
	cfg.KMS.Local.MasterKeyEnv = liftMasterKeyEnv
	cfg.KMS.Local.KeyStorePath = filepath.Join(t.TempDir(), "keys")
	cfg.Auth.JWTSigningKeyEnv = liftJWTKeyEnv
	cfg.Auth.Revocation.FilePath = filepath.Join(t.TempDir(), "revocations.json")
	if opts.defaultRPM > 0 {
		cfg.RateLimit.DefaultRPM = opts.defaultRPM
	}
	if opts.maxConcurrency > 0 {
		cfg.RateLimit.DefaultMaxConcurrency = opts.maxConcurrency
	}
	cfg.Providers = nil
	cfg.Egress.AllowedDomains = nil

	var mockURL string
	for _, provider := range opts.providers {
		upstream := httptest.NewUnstartedServer(provider.handler)
		upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		upstream.StartTLS()
		t.Cleanup(upstream.Close)
		roots.AddCert(upstream.Certificate())
		if mockURL == "" {
			mockURL = upstream.URL
		}
		cfg.Providers = append(cfg.Providers, config.Provider{
			ID:       provider.id,
			Name:     provider.id,
			Type:     gatewayconst.ProviderTypeOpenAI,
			BaseURL:  upstream.URL,
			APIKeyID: provider.keyID,
			Models:   []string{liftChatModel},
			Priority: provider.priority,
			Enabled:  true,
		})
		cfg.Egress.AllowedDomains = append(cfg.Egress.AllowedDomains, upstream.Listener.Addr().String())
	}

	if opts.adminEnabled {
		cfg.Admin = config.AdminConfig{
			Enabled:  true,
			Address:  reserveLoopbackAddr(t),
			TokenEnv: liftAdminTokenEnv,
		}
	}

	if _, err := revocation.NewWriter(cfg.Auth.Revocation.FilePath, 2*time.Second).Init(context.Background(), time.Now()); err != nil {
		t.Fatalf("initialize revocation state: %v", err)
	}

	seedStore, err := newKMSProvider(cfg.KMS)
	if err != nil {
		t.Fatalf("open seed KMS: %v", err)
	}
	for _, provider := range opts.providers {
		if err := seedStore.StoreKey(context.Background(), provider.keyID, []byte(provider.secret)); err != nil {
			_ = seedStore.Close()
			t.Fatalf("seed provider key: %v", err)
		}
	}
	if err := seedStore.Close(); err != nil {
		t.Fatalf("close seed KMS: %v", err)
	}

	srv, err := newServer(cfg, nil, roots)
	if err != nil {
		t.Fatalf("build runtime server: %v", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()

	env := &liftRuntime{
		client:     &http.Client{Timeout: liftClientTimeout},
		gatewayURL: "http://" + cfg.Server.Address,
		mockURL:    mockURL,
		jwtKey:     []byte(liftJWTSigningKey),
		cancel:     cancel,
		runErr:     runErr,
	}
	if opts.adminEnabled {
		env.adminURL = "http://" + cfg.Admin.Address
	}
	waitHTTPStatus(t, env.client, env.gatewayURL+gatewayconst.PathHealth, nil, http.StatusOK)
	if opts.adminEnabled {
		headers := http.Header{}
		headers.Set(liftAdminTokenHeader, liftAdminTokenValue)
		waitHTTPStatus(t, env.client, env.adminURL+liftAdminHealthPath, headers, http.StatusOK)
	}
	return env
}

// token signs a pool virtual key for lift e2e calls.
func (g *liftRuntime) token(t *testing.T, rpm, concurrency int) string {
	t.Helper()
	now := time.Now()
	return signRuntimeTestToken(t, g.jwtKey, middleware.VirtualKeyClaims{
		KeyID:          "virtual-key-lift",
		Subject:        "operator-lift",
		Models:         []string{liftChatModel},
		MaxRPM:         rpm,
		MaxConcurrency: concurrency,
		KeySource:      middleware.KeySourcePool,
		IssuedAt:       now.Add(-time.Minute).Unix(),
		ExpiresAt:      now.Add(time.Hour).Unix(),
		Issuer:         "aegis",
	})
}

func liftChat(t *testing.T, env *liftRuntime, body string) (*http.Response, []byte) {
	t.Helper()
	return liftChatWithToken(t, env, env.token(t, 0, 0), body)
}

func liftChatWithToken(t *testing.T, env *liftRuntime, token, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.gatewayURL+gatewayconst.PathChatCompletions, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build chat request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", gatewayconst.JSONContentType)
	resp, err := env.client.Do(req)
	if err != nil {
		t.Fatalf("chat request: %v", err)
	}
	payload, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read chat response: %v", readErr)
	}
	return resp, payload
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen(gatewayconst.AdminListenNetwork, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback address: %v", err)
	}
	return addr
}

func waitHTTPStatus(t *testing.T, client *http.Client, rawURL string, header http.Header, want int) {
	t.Helper()
	waitHTTPStatusAttempts(t, client, rawURL, header, want, liftHealthAttempts, liftHealthRetry)
}

func waitHTTPStatusAttempts(
	t *testing.T,
	client *http.Client,
	rawURL string,
	header http.Header,
	want int,
	attempts int,
	retry time.Duration,
) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("build readiness request: %v", err)
		}
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(retry)
	}
	t.Fatalf("endpoint %s did not reach status %d: %v", rawURL, want, lastErr)
}

// durationPercentile returns a nearest-rank percentile from samples.
func durationPercentile(samples []time.Duration, percentile int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	if percentile < 0 {
		percentile = 0
	}
	if percentile > liftPercentileMax {
		percentile = liftPercentileMax
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := (percentile * (len(sorted) - 1)) / liftPercentileMax
	return sorted[idx]
}
