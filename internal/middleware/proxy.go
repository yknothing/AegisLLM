package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/yknothing/AegisLLM/internal/proxy"
	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/utils"
)

type proxyEngine interface {
	ProxyRequest(
		ctx context.Context,
		w http.ResponseWriter,
		originalReq *http.Request,
		targetURL string,
		apiKey *utils.SecureBytes,
		isStreaming bool,
	) (*proxy.ProxyResult, error)
}

// Proxy creates the terminal middleware that forwards requests upstream.
func Proxy(engine proxyEngine) server.Middleware {
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
			ctx.ProviderResponded = true
			ctx.ProviderFailure = result.StatusCode == http.StatusTooManyRequests || result.StatusCode >= http.StatusInternalServerError
			ctx.StatusCode = result.StatusCode
			ctx.InputTokens = int(result.InputTokens)
			ctx.OutputTokens = int(result.OutputTokens)
		}
		if err != nil {
			if errors.Is(err, proxy.ErrUpstreamTransport) || errors.Is(err, proxy.ErrUpstreamRead) {
				ctx.ProviderFailure = true
			}
			ctx.StatusCode = http.StatusBadGateway
			if result != nil {
				// The upstream response may already have been partially written.
				// Preserve failure accounting without appending a second JSON body.
				return
			}
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
	if rel.IsAbs() || rel.Host != "" || rel.User != nil {
		return "", fmt.Errorf("target path must not include scheme or host")
	}
	if !strings.HasPrefix(targetPath, "/") {
		return "", fmt.Errorf("target path must be root-relative")
	}

	return base.ResolveReference(rel).String(), nil
}
