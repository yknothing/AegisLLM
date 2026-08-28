package middleware

import (
	"errors"
	"net/http"
	"sync"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/server"
)

// ProtocolAdapter transforms requests/responses between formats.
type ProtocolAdapter interface {
	Name() string
	TransformRequest(body []byte, model, apiVersion string) ([]byte, string, error)
	TransformResponse(body []byte) ([]byte, error)
	TransformStreamLine(line string) (string, bool, error)
	SupportsStreaming() bool
	AuthHeader() (name, prefix string)
	ExtraHeaders() map[string]string
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
	reg.Register(&OpenAIAdapter{})
	reg.Register(&DeepSeekAdapter{})
	reg.Register(&OpenRouterAdapter{})
	reg.Register(&AzureAdapter{})
	reg.Register(&AnthropicAdapter{})
	reg.Register(&GeminiAdapter{})
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

		transformed, targetPath, err := adapter.TransformRequest(body, ctx.Model, ctx.ProviderAPIVersion)
		if err != nil {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid provider request","type":"invalid_request_error"}}`))
			return
		}
		replaceRequestBody(ctx, transformed)
		ctx.ProviderType = providerType
		ctx.TargetPath = targetPath
		authName, authPrefix := adapter.AuthHeader()
		ctx.UpstreamAuthHeader = authName
		ctx.UpstreamAuthPrefix = authPrefix
		ctx.UpstreamExtraHeaders = adapter.ExtraHeaders()
		ctx.TransformResponse = adapter.TransformResponse
		ctx.TransformStreamLine = adapter.TransformStreamLine

		next()
	}
}

func bearerAuth() (string, string) {
	return gatewayconst.AuthHeaderAuthorization, gatewayconst.AuthSchemeBearerPrefix
}

func passthroughStreamLine(line string) (string, bool, error) {
	return line, false, nil
}
