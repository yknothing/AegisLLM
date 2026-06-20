// Package proxy implements the streaming proxy engine for Aegis.
//
// DESIGN:
//   - Asynchronous, non-blocking SSE (Server-Sent Events) forwarding
//   - Real-time token counting without breaking the stream
//   - Zero-copy forwarding where possible
//   - Automatic timeout and cancellation propagation
//
// SECURITY:
//   - Never buffers complete response bodies in memory
//   - API keys are injected per-request and zeroed after the upstream request is sent
//   - Response bodies are never logged (only token counts)
//   - Egress validation ensures requests only go to allowed domains
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yknothing/AegisLLM/internal/egress"
	"github.com/yknothing/AegisLLM/internal/requestid"
	"github.com/yknothing/AegisLLM/internal/utils"
)

// StreamConfig configures the streaming proxy engine.
type StreamConfig struct {
	// MaxRequestBodySize limits input size to prevent memory exhaustion.
	MaxRequestBodySize int64 // Default: 10MB

	// StreamTimeout is the maximum duration for a streaming response.
	StreamTimeout time.Duration // Default: 5 minutes

	// AllowedDomains restricts outbound connections (egress filtering).
	// SECURITY: Only these domains can be contacted.
	AllowedDomains []string
}

// Engine is the core streaming proxy that forwards requests to LLM providers.
type Engine struct {
	client *http.Client
	config StreamConfig
}

var allowedRequestHeaders = map[string]struct{}{
	"Accept":       {},
	"Content-Type": {},
	"User-Agent":   {},
}

var allowedResponseHeaders = map[string]struct{}{
	"Content-Type":                   {},
	"Openai-Processing-Ms":           {},
	"Openai-Version":                 {},
	"Ratelimit-Limit":                {},
	"Ratelimit-Remaining":            {},
	"Ratelimit-Reset":                {},
	"Retry-After":                    {},
	"X-Ratelimit-Limit-Tokens":       {},
	"X-Ratelimit-Limit-Requests":     {},
	"X-Ratelimit-Remaining-Tokens":   {},
	"X-Ratelimit-Remaining-Requests": {},
	"X-Ratelimit-Reset-Tokens":       {},
	"X-Ratelimit-Reset-Requests":     {},
}

var renamedResponseHeaders = map[string]string{
	http.CanonicalHeaderKey(requestid.Header): requestid.UpstreamHeader,
}

const (
	sseScannerInitialBufferSize = 64 * 1024
	sseScannerMaxLineSize       = 1 << 20
)

// NewEngine creates a new streaming proxy engine.
func NewEngine(cfg StreamConfig) *Engine {
	if cfg.MaxRequestBodySize <= 0 {
		cfg.MaxRequestBodySize = 10 << 20
	}
	if cfg.StreamTimeout <= 0 {
		cfg.StreamTimeout = 5 * time.Minute
	}

	// Configure HTTP client with security-hardened settings
	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	client := &http.Client{
		Transport: transport,
		// No default timeout - managed per-request via context
		// CheckRedirect prevents open redirect attacks
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Engine{
		client: client,
		config: cfg,
	}
}

// ProxyRequest forwards a request to the upstream LLM provider.
// It handles both streaming (SSE) and non-streaming responses.
//
// SECURITY:
//   - apiKey is zeroed after the request is sent
//   - Only allowed domains are contacted
//   - Response body is never fully buffered
func (e *Engine) ProxyRequest(
	ctx context.Context,
	w http.ResponseWriter,
	originalReq *http.Request,
	targetURL string,
	apiKey *utils.SecureBytes,
	isStreaming bool,
) (*ProxyResult, error) {
	if apiKey == nil {
		return nil, fmt.Errorf("provider API key is missing")
	}

	// SECURITY: Validate target domain against allowlist
	if err := e.validateEgress(targetURL); err != nil {
		return nil, fmt.Errorf("egress blocked: %w", err)
	}

	// Build upstream request
	upstreamReq, err := http.NewRequestWithContext(ctx,
		originalReq.Method,
		targetURL,
		originalReq.Body,
	)
	if err != nil {
		return nil, fmt.Errorf("creating upstream request: %w", err)
	}

	// Copy safe headers (exclude hop-by-hop and sensitive headers)
	copyHeaders(upstreamReq.Header, originalReq.Header)

	// Inject API key for the outbound request. The header string cannot be
	// zeroed by Go, so remove the header and close SecureBytes as soon as the
	// transport returns response headers.
	upstreamReq.Header.Set("Authorization", "Bearer "+string(apiKey.Bytes()))

	// Set request timeout
	reqCtx, cancel := context.WithTimeout(ctx, e.config.StreamTimeout)
	defer cancel()
	upstreamReq = upstreamReq.WithContext(reqCtx)

	// Execute request
	resp, err := e.client.Do(upstreamReq) // #nosec G704 -- targetURL is parsed, HTTPS-only, and host-allowlisted by validateEgress above.
	upstreamReq.Header.Del("Authorization")
	apiKey.Close()
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	result := &ProxyResult{
		StatusCode: resp.StatusCode,
	}

	if isStreaming && resp.StatusCode == http.StatusOK {
		// Stream SSE response with real-time token counting
		result.OutputTokens, err = e.streamSSE(w, resp)
		if err != nil {
			return result, fmt.Errorf("streaming failed: %w", err)
		}
	} else {
		// Non-streaming: forward response directly
		if err := e.forwardResponse(w, resp); err != nil {
			return result, fmt.Errorf("forwarding response failed: %w", err)
		}
	}

	return result, nil
}

// streamSSE forwards Server-Sent Events while counting tokens in real-time.
// DESIGN: Each SSE chunk is parsed for token usage without buffering the full response.
func (e *Engine) streamSSE(w http.ResponseWriter, resp *http.Response) (int64, error) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return 0, fmt.Errorf("response writer does not support flushing")
	}

	var tokenCount atomic.Int64
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, sseScannerInitialBufferSize), sseScannerMaxLineSize)

	for scanner.Scan() {
		line := scanner.Text()

		// Forward the line immediately (zero-copy semantics)
		_, err := fmt.Fprintf(w, "%s\n", line)
		if err != nil {
			return tokenCount.Load(), fmt.Errorf("write to client failed: %w", err)
		}
		flusher.Flush()

		// Parse SSE data lines for token counting
		if strings.HasPrefix(line, "data: ") {
			data := line[6:]
			if data == "[DONE]" {
				break
			}
			// Count tokens from the chunk (provider-specific parsing)
			tokens := countTokensFromChunk(data)
			tokenCount.Add(int64(tokens))
		}
	}

	if err := scanner.Err(); err != nil {
		return tokenCount.Load(), fmt.Errorf("reading upstream stream: %w", err)
	}

	return tokenCount.Load(), nil
}

// forwardResponse copies a non-streaming response to the client.
func (e *Engine) forwardResponse(w http.ResponseWriter, resp *http.Response) error {
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Stream body without full buffering
	if _, err := io.Copy(w, resp.Body); err != nil {
		return err
	}
	return nil
}

// validateEgress checks if the target URL's domain is in the allowlist.
// SECURITY: This constrains normal proxy execution to configured provider hosts.
func (e *Engine) validateEgress(targetURL string) error {
	if len(e.config.AllowedDomains) == 0 {
		return fmt.Errorf("no egress allowlist configured")
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("target URL must use https")
	}
	host := egress.NormalizeHost(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("target URL has no host")
	}

	if egress.HostAllowed(host, e.config.AllowedDomains) {
		return nil
	}

	return fmt.Errorf("domain not in egress allowlist: %s", host)
}

// copyHeaders copies the minimal safe client headers needed by provider APIs.
// SECURITY: This is an allowlist so ingress, proxy, auth, cookie, trace, and
// tenant/account headers cannot be reflected to upstream providers.
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if _, allowed := allowedRequestHeaders[http.CanonicalHeaderKey(key)]; !allowed {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

// copyResponseHeaders copies only the upstream response headers in Aegis's
// client contract. SECURITY: This is an allowlist so provider cookies, auth
// challenges, proxy metadata, debug headers, and tenant/account headers are not
// reflected downstream by default.
func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		canonicalKey := http.CanonicalHeaderKey(key)
		targetKey, renamed := renamedResponseHeaders[canonicalKey]
		if !renamed {
			if _, allowed := allowedResponseHeaders[canonicalKey]; !allowed {
				continue
			}
			targetKey = key
		}
		for _, v := range values {
			if renamed && !requestid.Safe(v) {
				continue
			}
			dst.Add(targetKey, v)
		}
	}
}

// countTokensFromChunk estimates token count from an SSE data chunk.
// This is a simplified heuristic; production should use tiktoken or similar.
func countTokensFromChunk(data string) int {
	// Reserved improvement: provider-specific token counting.
	// OpenAI format: {"choices":[{"delta":{"content":"..."}}]}
	// Each chunk typically contains 1 token
	if strings.Contains(data, `"content"`) {
		return 1
	}
	return 0
}

// ProxyResult contains the outcome of a proxied request.
type ProxyResult struct {
	StatusCode   int
	InputTokens  int64
	OutputTokens int64
	Duration     time.Duration
}
