package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yknothing/AegisLLM/internal/proxy"
	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/utils"
)

func TestProxyAbortsWhenUpstreamRequestFailsBeforeResponse(t *testing.T) {
	engine := stubProxyEngine{err: fmt.Errorf("dial failed: %w", proxy.ErrUpstreamTransport)}
	ctx := proxyTestContext()

	Proxy(engine)(ctx, func() {})

	if !ctx.IsAborted() {
		t.Fatal("proxy middleware did not abort before-response upstream error")
	}
	if ctx.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusBadGateway)
	}
	if !ctx.ProviderFailure {
		t.Fatal("upstream transport failure was not recorded as a provider failure")
	}
}

func TestProxyDoesNotRecordLocalEngineErrorAsProviderFailure(t *testing.T) {
	ctx := proxyTestContext()

	Proxy(stubProxyEngine{err: errors.New("local proxy configuration error")})(ctx, func() {})

	if ctx.ProviderFailure {
		t.Fatal("local proxy error was recorded as a provider failure")
	}
}

func TestProxyMarksPartialUpstreamFailureAsBadGateway(t *testing.T) {
	engine := stubProxyEngine{
		result: &proxy.ProxyResult{StatusCode: http.StatusOK, OutputTokens: 7},
		err:    errors.New("stream failed"),
	}
	ctx := proxyTestContext()

	Proxy(engine)(ctx, func() {})

	if ctx.IsAborted() {
		t.Fatal("proxy middleware aborted after upstream response may have been written")
	}
	if ctx.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusBadGateway)
	}
	if ctx.OutputTokens != 7 {
		t.Fatalf("output tokens = %d, want 7", ctx.OutputTokens)
	}
	if ctx.ProviderFailure {
		t.Fatal("unclassified partial response error was recorded as a provider failure")
	}
}

func TestProxyRecordsUpstreamResponseReadFailure(t *testing.T) {
	engine := stubProxyEngine{
		result: &proxy.ProxyResult{StatusCode: http.StatusOK},
		err:    fmt.Errorf("stream interrupted: %w", proxy.ErrUpstreamRead),
	}
	ctx := proxyTestContext()

	Proxy(engine)(ctx, func() {})

	if !ctx.ProviderResponded {
		t.Fatal("provider response was not recorded")
	}
	if !ctx.ProviderFailure {
		t.Fatal("upstream response read failure was not recorded as a provider failure")
	}
	if ctx.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusBadGateway)
	}
}

func TestProxyRecordsProviderResponseOutcome(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		wantFailure bool
	}{
		{name: "success", status: http.StatusOK},
		{name: "rate limited", status: http.StatusTooManyRequests, wantFailure: true},
		{name: "server error", status: http.StatusServiceUnavailable, wantFailure: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := proxyTestContext()
			Proxy(stubProxyEngine{result: &proxy.ProxyResult{StatusCode: tt.status}})(ctx, func() {})

			if !ctx.ProviderResponded {
				t.Fatal("provider response was not recorded")
			}
			if ctx.ProviderFailure != tt.wantFailure {
				t.Fatalf("provider failure = %v, want %v", ctx.ProviderFailure, tt.wantFailure)
			}
		})
	}
}

func TestBuildTargetURLAcceptsRootRelativePath(t *testing.T) {
	got, err := buildTargetURL("https://api.openai.com/base", "/v1/chat/completions?stream=true")
	if err != nil {
		t.Fatalf("buildTargetURL returned error: %v", err)
	}
	want := "https://api.openai.com/v1/chat/completions?stream=true"
	if got != want {
		t.Fatalf("target URL = %q, want %q", got, want)
	}
}

func TestBuildTargetURLRejectsNetworkPathReference(t *testing.T) {
	if _, err := buildTargetURL("https://api.openai.com", "//evil.example/v1/chat/completions"); err == nil {
		t.Fatal("buildTargetURL accepted a network-path reference")
	}
}

func TestBuildTargetURLRejectsRelativePathWithoutLeadingSlash(t *testing.T) {
	if _, err := buildTargetURL("https://api.openai.com", "v1/chat/completions"); err == nil {
		t.Fatal("buildTargetURL accepted a path without a leading slash")
	}
}

type stubProxyEngine struct {
	result *proxy.ProxyResult
	err    error
}

func (s stubProxyEngine) ProxyRequest(
	ctx context.Context,
	w http.ResponseWriter,
	originalReq *http.Request,
	targetURL string,
	apiKey *utils.SecureBytes,
	isStreaming bool,
) (*proxy.ProxyResult, error) {
	return s.result, s.err
}

func proxyTestContext() *server.RequestContext {
	return &server.RequestContext{
		Writer:         httptest.NewRecorder(),
		Request:        httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		BaseURL:        "https://api.openai.com",
		TargetPath:     "/v1/chat/completions",
		ProviderAPIKey: utils.NewSecureBytes([]byte("provider-secret")),
	}
}
