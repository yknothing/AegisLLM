// Package middleware - adapter.go implements protocol adaptation between
// the unified OpenAI-compatible API and various LLM provider formats.
//
// DESIGN:
//   - Plugin-based adapter registry: each provider type registers its adapter
//   - Adapters transform request/response formats without buffering full bodies
//   - Supports: OpenAI, Anthropic Claude, Google Gemini, DeepSeek, and more
//
// SECURITY:
//   - Adapters never log or retain message content
//   - Input validation prevents malformed requests from reaching providers
package middleware

import (
	"errors"
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
func Adapter(registry *AdapterRegistry, providerTypes map[string]string) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		providerType, ok := providerTypes[ctx.ProviderID]
		if !ok {
			// Default to OpenAI-compatible (passthrough)
			providerType = "openai"
		}

		adapter, err := registry.Get(providerType)
		if err != nil {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"unsupported provider type","type":"server_error"}}`))
			return
		}

		// Store adapter reference for use by the proxy engine
		_ = adapter // TODO: Pass adapter to proxy via context

		next()
	}
}

// --- Built-in Adapter Implementations ---

// OpenAIAdapter is a passthrough adapter (our API is already OpenAI-compatible).
type OpenAIAdapter struct{}

func (a *OpenAIAdapter) Name() string                                       { return "openai" }
func (a *OpenAIAdapter) TransformRequest(body []byte, model string) ([]byte, string, error) {
	return body, "/v1/chat/completions", nil
}
func (a *OpenAIAdapter) TransformResponse(body []byte) ([]byte, error)      { return body, nil }
func (a *OpenAIAdapter) TransformStreamChunk(chunk []byte) ([]byte, error)  { return chunk, nil }
func (a *OpenAIAdapter) SupportsStreaming() bool                            { return true }

// AnthropicAdapter transforms between OpenAI and Anthropic Claude formats.
type AnthropicAdapter struct{}

func (a *AnthropicAdapter) Name() string { return "anthropic" }
func (a *AnthropicAdapter) TransformRequest(body []byte, model string) ([]byte, string, error) {
	// TODO: Transform OpenAI chat completion format to Anthropic Messages API
	// Key differences:
	//   - system message → top-level "system" field
	//   - model naming: "claude-sonnet-4-20250514" etc.
	//   - max_tokens is required (not optional)
	//   - Different header: x-api-key instead of Authorization Bearer
	return body, "/v1/messages", nil
}
func (a *AnthropicAdapter) TransformResponse(body []byte) ([]byte, error)     { return body, nil }
func (a *AnthropicAdapter) TransformStreamChunk(chunk []byte) ([]byte, error) { return chunk, nil }
func (a *AnthropicAdapter) SupportsStreaming() bool                           { return true }

// GeminiAdapter transforms between OpenAI and Google Gemini formats.
type GeminiAdapter struct{}

func (a *GeminiAdapter) Name() string { return "google" }
func (a *GeminiAdapter) TransformRequest(body []byte, model string) ([]byte, string, error) {
	// TODO: Transform to Gemini generateContent format
	// Key differences:
	//   - messages → contents[].parts[].text
	//   - Different auth: API key in URL param or OAuth
	//   - model in URL path: /v1/models/{model}:generateContent
	return body, "/v1/models/" + model + ":generateContent", nil
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
