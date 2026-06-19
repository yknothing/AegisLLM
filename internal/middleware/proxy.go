package middleware

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/yknothing/AegisLLM/internal/proxy"
	"github.com/yknothing/AegisLLM/internal/server"
)

// Proxy creates the terminal middleware that forwards requests upstream.
func Proxy(engine *proxy.Engine) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		if engine == nil {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"proxy engine unavailable","type":"server_error"}}`))
			return
		}
		if ctx.BaseURL == "" || ctx.ProviderAPIKey == nil {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"incomplete proxy context","type":"server_error"}}`))
			return
		}

		targetURL, err := buildTargetURL(ctx.BaseURL, ctx.TargetPath)
		if err != nil {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"invalid provider target","type":"server_error"}}`))
			return
		}

		result, err := engine.ProxyRequest(
			ctx.Request.Context(),
			ctx.Writer,
			ctx.Request,
			targetURL,
			ctx.ProviderAPIKey,
			ctx.IsStreaming,
		)
		if result != nil {
			ctx.StatusCode = result.StatusCode
			ctx.InputTokens = int(result.InputTokens)
			ctx.OutputTokens = int(result.OutputTokens)
		}
		if err != nil && result == nil {
			ctx.Abort(http.StatusBadGateway, []byte(`{"error":{"message":"upstream request failed","type":"server_error"}}`))
			return
		}
	}
}

func buildTargetURL(baseURL, targetPath string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("base URL must be absolute")
	}

	if targetPath == "" {
		targetPath = "/"
	}
	rel, err := url.Parse(targetPath)
	if err != nil {
		return "", fmt.Errorf("parsing target path: %w", err)
	}
	if rel.IsAbs() {
		return "", fmt.Errorf("target path must be relative")
	}

	return base.ResolveReference(rel).String(), nil
}
