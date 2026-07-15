// Package middleware - adapter.go implements protocol adaptation between
// the unified OpenAI-compatible API and various LLM provider formats.
//
// DESIGN:
//   - Plugin-based adapter registry: each provider type registers its adapter
//   - Adapters transform bounded request bodies up to max_request_body_size
//   - Current runtime support: OpenAI-compatible OpenAI and DeepSeek.
//   - Anthropic and Gemini adapter types are reserved until implemented.
//
// SECURITY:
//   - Adapters never log or retain message content
//   - Input validation prevents malformed requests from reaching providers
package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/yknothing/AegisLLM/internal/server"
)

// ProtocolAdapter transforms requests/responses between formats.
type ProtocolAdapter interface {
	// Name returns the adapter identifier (e.g., "openai", "anthropic").
	Name() string

	// TransformRequest converts an OpenAI-format request to the provider's format.
	// Returns the transformed body and target URL path.
	TransformRequest(body []byte, model string) ([]byte, string, error)

	// TransformResponse converts the provider's response to OpenAI format.
	// For streaming, this is called per-chunk.
	TransformResponse(body []byte) ([]byte, error)

	// TransformStreamChunk converts a single SSE chunk to OpenAI format.
	TransformStreamChunk(chunk []byte) ([]byte, error)

	// SupportsStreaming returns whether this provider supports SSE streaming.
	SupportsStreaming() bool
}

// AdapterRegistry manages protocol adapters for different provider types.
type AdapterRegistry struct {
	mu       sync.RWMutex
	adapters map[string]ProtocolAdapter
}

// NewAdapterRegistry creates a new adapter registry with built-in adapters.
func NewAdapterRegistry() *AdapterRegistry {
	reg := &AdapterRegistry{
		adapters: make(map[string]ProtocolAdapter),
	}

	// Register built-in adapters
	reg.Register(&OpenAIAdapter{})
	reg.Register(&AnthropicAdapter{})
	reg.Register(&GeminiAdapter{})
	reg.Register(&DeepSeekAdapter{})

	return reg
}

// Register adds a new adapter to the registry.
func (r *AdapterRegistry) Register(adapter ProtocolAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[adapter.Name()] = adapter
}

// Get retrieves an adapter by provider type.
func (r *AdapterRegistry) Get(providerType string) (ProtocolAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, ok := r.adapters[providerType]
	if !ok {
		return nil, errors.New("no adapter registered for provider type: " + providerType)
	}
	return adapter, nil
}

// Adapter creates the protocol adaptation middleware.
func Adapter(registry *AdapterRegistry, providerTypes map[string]string, maxRequestBodySize int64) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		providerType, ok := providerTypes[ctx.ProviderID]
		if !ok {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"unsupported provider type","type":"server_error"}}`))
			return
		}

		adapter, err := registry.Get(providerType)
		if err != nil {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"unsupported provider type","type":"server_error"}}`))
			return
		}

		body, err := readRequestBody(ctx, maxRequestBodySize)
		if errors.Is(err, errRequestBodyTooLarge) {
			ctx.Abort(http.StatusRequestEntityTooLarge, []byte(`{"error":{"message":"request body too large","type":"invalid_request_error"}}`))
			return
		}
		if err != nil {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid request body","type":"invalid_request_error"}}`))
			return
		}

		transformed, targetPath, err := adapter.TransformRequest(body, ctx.Model)
		if err != nil {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid provider request","type":"invalid_request_error"}}`))
			return
		}
		replaceRequestBody(ctx, transformed)
		ctx.ProviderType = providerType
		ctx.TargetPath = targetPath

		next()
	}
}

// --- Built-in Adapter Implementations ---

// OpenAIAdapter is a passthrough adapter (our API is already OpenAI-compatible).
type OpenAIAdapter struct{}

func (a *OpenAIAdapter) Name() string { return "openai" }
func (a *OpenAIAdapter) TransformRequest(body []byte, model string) ([]byte, string, error) {
	return body, "/v1/chat/completions", nil
}
func (a *OpenAIAdapter) TransformResponse(body []byte) ([]byte, error)     { return body, nil }
func (a *OpenAIAdapter) TransformStreamChunk(chunk []byte) ([]byte, error) { return chunk, nil }
func (a *OpenAIAdapter) SupportsStreaming() bool                           { return true }

// AnthropicAdapter transforms between OpenAI and Anthropic Claude formats.
type AnthropicAdapter struct{}

func (a *AnthropicAdapter) Name() string { return "anthropic" }
func (a *AnthropicAdapter) TransformRequest(body []byte, model string) ([]byte, string, error) {
	// Reserved implementation point: transform OpenAI chat completion format
	// to the Anthropic Messages API.
	// Key differences:
	//   - system message → top-level "system" field
	//   - model naming: "claude-sonnet-4-20250514" etc.
	//   - max_tokens is required (not optional)
	//   - Different header: x-api-key instead of Authorization Bearer
	return nil, "", fmt.Errorf("anthropic adapter is not implemented")
}
func (a *AnthropicAdapter) TransformResponse(body []byte) ([]byte, error)     { return body, nil }
func (a *AnthropicAdapter) TransformStreamChunk(chunk []byte) ([]byte, error) { return chunk, nil }
func (a *AnthropicAdapter) SupportsStreaming() bool                           { return true }

// GeminiAdapter transforms between OpenAI and Google Gemini formats.
type GeminiAdapter struct{}

func (a *GeminiAdapter) Name() string { return "google" }
func (a *GeminiAdapter) TransformRequest(body []byte, model string) ([]byte, string, error) {
	// Reserved implementation point: transform to Gemini generateContent format.
	// Key differences:
	//   - messages → contents[].parts[].text
	//   - Different auth: API key in URL param or OAuth
	//   - model in URL path: /v1/models/{model}:generateContent
	return nil, "", fmt.Errorf("google adapter is not implemented")
}
func (a *GeminiAdapter) TransformResponse(body []byte) ([]byte, error)     { return body, nil }
func (a *GeminiAdapter) TransformStreamChunk(chunk []byte) ([]byte, error) { return chunk, nil }
func (a *GeminiAdapter) SupportsStreaming() bool                           { return true }

// DeepSeekAdapter is OpenAI-compatible (passthrough with minor adjustments).
type DeepSeekAdapter struct{}

func (a *DeepSeekAdapter) Name() string { return "deepseek" }
func (a *DeepSeekAdapter) TransformRequest(body []byte, model string) ([]byte, string, error) {
	// DeepSeek is OpenAI-compatible, minimal transformation needed
	return body, "/v1/chat/completions", nil
}
func (a *DeepSeekAdapter) TransformResponse(body []byte) ([]byte, error)     { return body, nil }
func (a *DeepSeekAdapter) TransformStreamChunk(chunk []byte) ([]byte, error) { return chunk, nil }
func (a *DeepSeekAdapter) SupportsStreaming() bool                           { return true }
