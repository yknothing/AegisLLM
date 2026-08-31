package middleware

import (
	"net/url"
	"strings"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
)

const azureChatCompletionsSuffix = "/chat/completions"

// AzureAdapter maps OpenAI chat completions onto Azure OpenAI deployment URLs.
type AzureAdapter struct{}

func (a *AzureAdapter) Name() string { return gatewayconst.ProviderTypeAzure }

func (a *AzureAdapter) TransformRequest(body []byte, model, apiVersion string) ([]byte, string, error) {
	if strings.TrimSpace(apiVersion) == "" {
		apiVersion = gatewayconst.DefaultAzureOpenAIAPIVersion
	}
	query := url.Values{}
	query.Set(gatewayconst.AzureOpenAIAPIVersionQuery, apiVersion)
	path := "/openai/deployments/" + url.PathEscape(model) + azureChatCompletionsSuffix + "?" + query.Encode()
	return body, path, nil
}

func (a *AzureAdapter) TransformResponse(body []byte) ([]byte, error) { return body, nil }
func (a *AzureAdapter) TransformStreamLine(line string) (string, bool, error) {
	return passthroughStreamLine(line)
}
func (a *AzureAdapter) SupportsStreaming() bool { return true }
func (a *AzureAdapter) AuthHeader() (string, string) {
	return gatewayconst.AuthHeaderAzureKey, ""
}
func (a *AzureAdapter) ExtraHeaders() map[string]string { return nil }
