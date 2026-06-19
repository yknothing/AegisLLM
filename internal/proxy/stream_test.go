package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateEgressRequiresAllowlist(t *testing.T) {
	engine := NewEngine(StreamConfig{})

	if err := engine.validateEgress("https://api.openai.com/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted a target with no allowlist")
	}
}

func TestValidateEgressMatchesNormalizedHost(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("https://api.openai.com/v1/chat/completions"); err != nil {
		t.Fatalf("validateEgress rejected allowed host: %v", err)
	}
}

func TestValidateEgressRejectsSubstringBypass(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("https://api.openai.com.evil.example/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted substring host bypass")
	}
}

func TestValidateEgressRejectsNonHTTPS(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("http://api.openai.com/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted non-HTTPS egress")
	}
}

func TestNewEngineRequiresTLS13ForUpstreamTransport(t *testing.T) {
	engine := NewEngine(StreamConfig{})

	transport, ok := engine.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", engine.client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
}

func TestCopyHeadersAllowsOnlySafeProviderRequestHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("Accept", "application/json")
	src.Set("Content-Type", "application/json")
	src.Set("Authorization", "Bearer client")
	src.Set("X-Api-Key", "client-key")
	src.Set("X-Admin-Token", "admin-token")
	src.Set("OpenAI-Organization", "org-client")
	src.Set("OpenAI-Project", "proj-client")
	src.Set("X-Request-Id", "req-client")
	src.Set("X-Forwarded-For", "203.0.113.1")
	src.Set("X-Forwarded-Host", "internal.example")
	src.Set("X-Forwarded-Proto", "http")
	src.Set("Forwarded", "for=203.0.113.1")
	src.Set("Keep-Alive", "timeout=5")
	src.Set("Te", "trailers")
	src.Set("Trailer", "Expires")
	src.Set("Transfer-Encoding", "chunked")
	src.Set("Upgrade", "websocket")
	src.Set("User-Agent", "aegis-test")

	dst := http.Header{}
	copyHeaders(dst, src)

	for _, header := range []string{
		"Authorization",
		"X-Api-Key",
		"X-Admin-Token",
		"OpenAI-Organization",
		"OpenAI-Project",
		"X-Request-Id",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Forwarded",
		"Keep-Alive",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		if got := dst.Get(header); got != "" {
			t.Fatalf("copyHeaders forwarded sensitive header %s=%q", header, got)
		}
	}
	if got := dst.Get("Accept"); got != "application/json" {
		t.Fatalf("copyHeaders stripped safe Accept header: %q", got)
	}
	if got := dst.Get("Content-Type"); got != "application/json" {
		t.Fatalf("copyHeaders stripped safe Content-Type header: %q", got)
	}
	if got := dst.Get("User-Agent"); got != "aegis-test" {
		t.Fatalf("copyHeaders stripped safe User-Agent header: %q", got)
	}
}

func TestForwardResponseStripsUnsafeUpstreamHeaders(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":        []string{"application/json"},
			"X-Request-Id":        []string{"req-upstream"},
			"Set-Cookie":          []string{"session=upstream"},
			"Connection":          []string{"close"},
			"Transfer-Encoding":   []string{"chunked"},
			"Proxy-Authenticate":  []string{"Basic realm=\"upstream\""},
			"Proxy-Authorization": []string{"Bearer upstream"},
			"Keep-Alive":          []string{"timeout=5"},
			"Te":                  []string{"trailers"},
			"Trailer":             []string{"Expires"},
			"Upgrade":             []string{"websocket"},
		},
		Body: io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}

	recorder := httptest.NewRecorder()
	if err := engine.forwardResponse(recorder, resp); err != nil {
		t.Fatalf("forwardResponse returned error: %v", err)
	}

	result := recorder.Result()
	defer func() {
		_ = result.Body.Close()
	}()
	for _, header := range []string{
		"Set-Cookie",
		"Connection",
		"Transfer-Encoding",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Keep-Alive",
		"Te",
		"Trailer",
		"Upgrade",
	} {
		if got := result.Header.Get(header); got != "" {
			t.Fatalf("forwardResponse copied unsafe header %s=%q", header, got)
		}
	}
	if got := result.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	if got := result.Header.Get("X-Request-Id"); got != "req-upstream" {
		t.Fatalf("request id = %q, want req-upstream", got)
	}
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q, want upstream body", body)
	}
}
