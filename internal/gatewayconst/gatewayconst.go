// Package gatewayconst holds cross-package AegisLift protocol and policy
// constants. Values here replace magic numbers in adapters, routing, and
// rate/quota enforcement.
package gatewayconst

import "time"

const (
	// Provider types accepted by the runtime adapter registry.
	ProviderTypeOpenAI     = "openai"
	ProviderTypeDeepSeek   = "deepseek"
	ProviderTypeAnthropic  = "anthropic"
	ProviderTypeGoogle     = "google"
	ProviderTypeAzure      = "azure"
	ProviderTypeOpenRouter = "openrouter"

	// OpenAI-compatible data-plane paths.
	PathChatCompletions = "/v1/chat/completions"
	PathModels          = "/v1/models"
	PathHealth          = "/health"

	// Provider-native paths.
	PathAnthropicMessages = "/v1/messages"

	// Upstream authentication headers. Secrets are never logged.
	AuthHeaderAuthorization = "Authorization"
	AuthSchemeBearerPrefix  = "Bearer "
	AuthHeaderAnthropicKey  = "x-api-key"
	AuthHeaderAzureKey      = "api-key"
	AuthHeaderGoogleAPIKey  = "x-goog-api-key" // #nosec G101 -- HTTP header name, not a credential.

	AnthropicVersionHeader = "anthropic-version"
	AnthropicAPIVersion    = "2023-06-01"

	// DefaultAnthropicMaxTokens is used when the client omits max_tokens.
	// Anthropic requires this field.
	DefaultAnthropicMaxTokens = 4096

	AzureOpenAIAPIVersionQuery   = "api-version"
	DefaultAzureOpenAIAPIVersion = "2024-10-21"

	GeminiGeneratePathPrefix = "/v1beta/models/"
	GeminiGenerateContent    = ":generateContent"
	GeminiStreamGenerate     = ":streamGenerateContent"

	RateDimensionRPM = "rpm"
	RateDimensionTPM = "tpm"

	// CharsPerTokenEstimate is the fail-closed TPM preflight heuristic.
	// Actual usage is reconciled after the proxy returns.
	CharsPerTokenEstimate = 4
	MinEstimatedTokens    = 1

	DefaultProviderWeight = 1

	CircuitBreakerFailureThreshold = int64(5)
	CircuitBreakerRecovery         = 30 * time.Second

	QuotaBackendMemory = "memory"

	JSONContentType = "application/json"

	OpenAIObjectList           = "list"
	OpenAIObjectModel          = "model"
	OpenAIObjectChatCompletion = "chat.completion"
	OpenAIObjectChatChunk      = "chat.completion.chunk"

	MessageRoleSystem    = "system"
	MessageRoleUser      = "user"
	MessageRoleAssistant = "assistant"
	GeminiRoleModel      = "model"

	FinishReasonStop   = "stop"
	FinishReasonLength = "length"

	AnthropicStopEndTurn = "end_turn"
	AnthropicStopMaxTok  = "max_tokens"

	// TokensPerMillion is the pricing unit used by the quota table.
	TokensPerMillion = 1_000_000.0

	AdminListenNetwork = "tcp"

	// MinAdminTokenBytes is the minimum admin-token length accepted at runtime.
	MinAdminTokenBytes = 32
	// MaxAdminRequestBytes bounds Admin JSON bodies. Secrets in BYOK stay unused.
	MaxAdminRequestBytes = 64 << 10

	// MaxCapturedResponseBytes bounds a buffered failover attempt.
	MaxCapturedResponseBytes = 4 << 20
)

// IsLoopbackHost reports whether host is a local-only admin bind target.
func IsLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

// IsSupportedProviderType reports whether the runtime has an adapter for type.
func IsSupportedProviderType(providerType string) bool {
	switch providerType {
	case ProviderTypeOpenAI, ProviderTypeDeepSeek, ProviderTypeAnthropic,
		ProviderTypeGoogle, ProviderTypeAzure, ProviderTypeOpenRouter:
		return true
	default:
		return false
	}
}

// HTTPRoute builds a Go 1.22+ ServeMux pattern from method and path.
func HTTPRoute(method, path string) string {
	return method + " " + path
}
