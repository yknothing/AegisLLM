package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/proxy"
	"github.com/yknothing/AegisLLM/internal/server"
)

type proxyEngine interface {
	Dispatch(
		ctx context.Context,
		w http.ResponseWriter,
		originalReq *http.Request,
		cfg proxy.DispatchConfig,
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

		writer := ctx.Writer
		var captured *captureWriter
		if ctx.CanFallback && !ctx.IsStreaming {
			captured = newCaptureWriter()
			writer = captured
		}

		result, err := engine.Dispatch(
			ctx.Request.Context(),
			writer,
			ctx.Request,
			proxy.DispatchConfig{
				TargetURL:           targetURL,
				APIKey:              ctx.ProviderAPIKey,
				IsStreaming:         ctx.IsStreaming,
				AuthHeader:          ctx.UpstreamAuthHeader,
				AuthPrefix:          ctx.UpstreamAuthPrefix,
				ExtraHeaders:        ctx.UpstreamExtraHeaders,
				TransformResponse:   ctx.TransformResponse,
				TransformStreamLine: ctx.TransformStreamLine,
				MaxTransformBytes:   gatewayconst.MaxCapturedResponseBytes,
			},
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
			if captured != nil && ctx.CanFallback && !ctx.ResponseCommitted() && isRetryableProxy(result, err) {
				ctx.RetryableAttempt = true
				return
			}
			if result != nil {
				if captured != nil && !ctx.ResponseCommitted() {
					captured.FlushTo(ctx.Writer)
				}
				return
			}
			ctx.Abort(http.StatusBadGateway, []byte(`{"error":{"message":"upstream request failed","type":"server_error"}}`))
			return
		}
		if captured != nil {
			if ctx.CanFallback && isRetryableStatus(captured.Status()) && !captured.Overflowed() {
				ctx.RetryableAttempt = true
				ctx.ProviderFailure = true
				return
			}
			captured.FlushTo(ctx.Writer)
		}
	}
}

func isRetryableProxy(result *proxy.ProxyResult, err error) bool {
	if errors.Is(err, proxy.ErrUpstreamTransport) {
		return true
	}
	if result == nil {
		return false
	}
	return isRetryableStatus(result.StatusCode)
}

func isRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
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
