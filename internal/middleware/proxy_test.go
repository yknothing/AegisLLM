package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yknothing/AegisLLM/internal/proxy"
	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/utils"
)

func TestProxyAbortsWhenUpstreamRequestFailsBeforeResponse(t *testing.T) {
	engine := stubProxyEngine{err: errors.New("dial failed")}
	ctx := proxyTestContext()

	Proxy(engine)(ctx, func() {})

	if !ctx.IsAborted() {
		t.Fatal("proxy middleware did not abort before-response upstream error")
	}
	if ctx.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusBadGateway)
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
