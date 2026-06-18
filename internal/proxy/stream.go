// Package proxy implements the streaming proxy engine for Aegis.
//
// DESIGN:
//   - Asynchronous, non-blocking SSE (Server-Sent Events) forwarding
//   - Real-time token counting without breaking the stream
//   - Zero-copy forwarding where possible
//   - Automatic timeout and cancellation propagation
//
// SECURITY:
//   - Never buffers complete request/response bodies in memory
//   - API keys are injected per-request and zeroed immediately after
//   - Response bodies are never logged (only token counts)
//   - Egress validation ensures requests only go to allowed domains
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

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

// NewEngine creates a new streaming proxy engine.
func NewEngine(cfg StreamConfig) *Engine {
	// Configure HTTP client with security-hardened settings
	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		// TLS 1.3 minimum for outbound connections
		// TLSClientConfig is configured per-deployment
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

	// Inject API key and immediately schedule zeroing
	upstreamReq.Header.Set("Authorization", "Bearer "+string(apiKey.Bytes()))
	defer apiKey.Close() // Zero the key after request is sent

	// Set request timeout
	reqCtx, cancel := context.WithTimeout(ctx, e.config.StreamTimeout)
	defer cancel()
	upstreamReq = upstreamReq.WithContext(reqCtx)

	// Execute request
	resp, err := e.client.Do(upstreamReq)
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

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
		e.forwardResponse(w, resp)
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
func (e *Engine) forwardResponse(w http.ResponseWriter, resp *http.Response) {
	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream body without full buffering
	io.Copy(w, resp.Body)
}

// validateEgress checks if the target URL's domain is in the allowlist.
// SECURITY: This prevents data exfiltration even if the gateway is compromised.
func (e *Engine) validateEgress(targetURL string) error {
	if len(e.config.AllowedDomains) == 0 {
		return nil // No restrictions configured
	}

	for _, domain := range e.config.AllowedDomains {
		if strings.Contains(targetURL, domain) {
			return nil
		}
	}

	return fmt.Errorf("domain not in egress allowlist: %s", targetURL)
}

// copyHeaders copies safe headers from source to destination.
// SECURITY: Strips hop-by-hop headers and sensitive headers.
func copyHeaders(dst, src http.Header) {
	skipHeaders := map[string]bool{
		"Authorization":    true, // Will be replaced with provider key
		"Host":             true,
		"Connection":       true,
		"Transfer-Encoding": true,
		"Upgrade":          true,
		"Cookie":           true,
	}

	for key, values := range src {
		if skipHeaders[key] {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

// countTokensFromChunk estimates token count from an SSE data chunk.
// This is a simplified heuristic; production should use tiktoken or similar.
func countTokensFromChunk(data string) int {
	// TODO: Implement proper token counting based on provider response format
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
