package middleware

import "github.com/yknothing/AegisLLM/internal/gatewayconst"

// OpenAIAdapter is a passthrough adapter (the public API is OpenAI-compatible).
type OpenAIAdapter struct{}

func (a *OpenAIAdapter) Name() string { return gatewayconst.ProviderTypeOpenAI }
func (a *OpenAIAdapter) TransformRequest(body []byte, model, apiVersion string) ([]byte, string, error) {
	return body, gatewayconst.PathChatCompletions, nil
}
func (a *OpenAIAdapter) TransformResponse(body []byte) ([]byte, error) { return body, nil }
func (a *OpenAIAdapter) TransformStreamLine(line string) (string, bool, error) {
	return passthroughStreamLine(line)
}
func (a *OpenAIAdapter) SupportsStreaming() bool         { return true }
func (a *OpenAIAdapter) AuthHeader() (string, string)    { return bearerAuth() }
func (a *OpenAIAdapter) ExtraHeaders() map[string]string { return nil }

// DeepSeekAdapter is OpenAI-compatible.
type DeepSeekAdapter struct{}

func (a *DeepSeekAdapter) Name() string { return gatewayconst.ProviderTypeDeepSeek }
func (a *DeepSeekAdapter) TransformRequest(body []byte, model, apiVersion string) ([]byte, string, error) {
	return body, gatewayconst.PathChatCompletions, nil
}
func (a *DeepSeekAdapter) TransformResponse(body []byte) ([]byte, error) { return body, nil }
func (a *DeepSeekAdapter) TransformStreamLine(line string) (string, bool, error) {
	return passthroughStreamLine(line)
}
func (a *DeepSeekAdapter) SupportsStreaming() bool         { return true }
func (a *DeepSeekAdapter) AuthHeader() (string, string)    { return bearerAuth() }
func (a *DeepSeekAdapter) ExtraHeaders() map[string]string { return nil }

// OpenRouterAdapter is OpenAI-compatible.
type OpenRouterAdapter struct{}

func (a *OpenRouterAdapter) Name() string { return gatewayconst.ProviderTypeOpenRouter }
func (a *OpenRouterAdapter) TransformRequest(body []byte, model, apiVersion string) ([]byte, string, error) {
	return body, gatewayconst.PathChatCompletions, nil
}
func (a *OpenRouterAdapter) TransformResponse(body []byte) ([]byte, error) { return body, nil }
func (a *OpenRouterAdapter) TransformStreamLine(line string) (string, bool, error) {
	return passthroughStreamLine(line)
}
func (a *OpenRouterAdapter) SupportsStreaming() bool         { return true }
func (a *OpenRouterAdapter) AuthHeader() (string, string)    { return bearerAuth() }
func (a *OpenRouterAdapter) ExtraHeaders() map[string]string { return nil }
