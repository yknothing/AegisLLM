package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/model"
	"github.com/yknothing/AegisLLM/internal/server"
)

func TestAdapterFailsClosedWhenProviderTypeMissing(t *testing.T) {
	ctx := &server.RequestContext{
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[]}`)),
		ProviderID: "openai-main",
		Model:      "gpt-4o",
	}

	calledNext := false
	Adapter(NewAdapterRegistry(), map[string]string{}, 1024)(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("Adapter called next with a missing provider type mapping")
	}
	if !ctx.IsAborted() {
		t.Fatal("Adapter did not fail closed for a missing provider type mapping")
	}
	if ctx.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusInternalServerError)
	}
}

func TestAdapterPassesThroughKnownOpenAIProviderType(t *testing.T) {
	ctx := &server.RequestContext{
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[]}`)),
		ProviderID: "openai-main",
		Model:      "gpt-4o",
	}

	calledNext := false
	Adapter(NewAdapterRegistry(), map[string]string{"openai-main": "openai"}, 1024)(ctx, func() {
		calledNext = true
	})

	if !calledNext {
		t.Fatal("Adapter did not call next for a known provider type mapping")
	}
	if ctx.IsAborted() {
		t.Fatal("Adapter aborted a known provider type mapping")
	}
	if ctx.ProviderType != "openai" {
		t.Fatalf("provider type = %q, want openai", ctx.ProviderType)
	}
	if ctx.TargetPath != "/v1/chat/completions" {
		t.Fatalf("target path = %q, want /v1/chat/completions", ctx.TargetPath)
	}
}

func TestAzureAdapterBuildsDeploymentPath(t *testing.T) {
	path, err := adapterTargetPath(t, "azure", "gpt-4o", "")
	if err != nil {
		t.Fatalf("azure adapter: %v", err)
	}
	if !strings.HasPrefix(path, "/openai/deployments/gpt-4o/chat/completions?") {
		t.Fatalf("azure path = %q", path)
	}
	if !strings.Contains(path, "api-version=") {
		t.Fatalf("azure path missing api-version: %q", path)
	}
}

func TestAnthropicAdapterUsesMessagesPath(t *testing.T) {
	path, err := adapterTargetPath(t, "anthropic", "claude-haiku-3-5", "")
	if err != nil {
		t.Fatalf("anthropic adapter: %v", err)
	}
	if path != "/v1/messages" {
		t.Fatalf("anthropic path = %q, want /v1/messages", path)
	}
}

func TestGeminiAdapterUsesGenerateContentPath(t *testing.T) {
	path, err := adapterTargetPath(t, "google", "gemini-2.5-flash", "")
	if err != nil {
		t.Fatalf("gemini adapter: %v", err)
	}
	if path != "/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("gemini path = %q", path)
	}
}

func TestOpenRouterAdapterUsesChatCompletionsPath(t *testing.T) {
	path, err := adapterTargetPath(t, gatewayconst.ProviderTypeOpenRouter, "openai/gpt-4o-mini", "")
	if err != nil {
		t.Fatalf("openrouter adapter: %v", err)
	}
	if path != gatewayconst.PathChatCompletions {
		t.Fatalf("openrouter path = %q, want %s", path, gatewayconst.PathChatCompletions)
	}
}

func TestAnthropicAdapterTransformResponseToOpenAIChat(t *testing.T) {
	native := `{"id":"msg_1","model":"claude-haiku-3-5","stop_reason":"end_turn","content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":3,"output_tokens":1}}`
	encoded, err := (&AnthropicAdapter{}).TransformResponse([]byte(native))
	if err != nil {
		t.Fatalf("TransformResponse: %v", err)
	}
	var out model.ChatCompletionResponse
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("decode openai response: %v", err)
	}
	if out.Object != gatewayconst.OpenAIObjectChatCompletion {
		t.Fatalf("object = %q, want %s", out.Object, gatewayconst.OpenAIObjectChatCompletion)
	}
	if len(out.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(out.Choices))
	}
	content, ok := out.Choices[0].Message.Content.(string)
	if !ok || content != "hello" {
		t.Fatalf("content = %#v, want hello", out.Choices[0].Message.Content)
	}
	if strings.Contains(string(encoded), `"content":[{"type"`) {
		t.Fatal("native Anthropic content array leaked into the client body")
	}
}

func TestAnthropicAdapterTransformStreamLineDelta(t *testing.T) {
	line := `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}`
	got, skip, err := (&AnthropicAdapter{}).TransformStreamLine(line)
	if err != nil {
		t.Fatalf("TransformStreamLine: %v", err)
	}
	if skip {
		t.Fatal("content_block_delta was skipped")
	}
	if !strings.HasPrefix(got, "data: ") {
		t.Fatalf("stream line = %q, want data prefix", got)
	}
	if !strings.Contains(got, gatewayconst.OpenAIObjectChatChunk) {
		t.Fatalf("stream line = %q, want openai chunk object", got)
	}
	if !strings.Contains(got, `"hi"`) {
		t.Fatalf("stream line = %q, want delta text", got)
	}
}

func TestGeminiAdapterTransformResponseToOpenAIChat(t *testing.T) {
	native := `{"candidates":[{"content":{"role":"model","parts":[{"text":"pong"}]}}]}`
	encoded, err := (&GeminiAdapter{}).TransformResponse([]byte(native))
	if err != nil {
		t.Fatalf("TransformResponse: %v", err)
	}
	var out model.ChatCompletionResponse
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("decode openai response: %v", err)
	}
	if out.Object != gatewayconst.OpenAIObjectChatCompletion {
		t.Fatalf("object = %q, want %s", out.Object, gatewayconst.OpenAIObjectChatCompletion)
	}
	if len(out.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(out.Choices))
	}
	content, ok := out.Choices[0].Message.Content.(string)
	if !ok || content != "pong" {
		t.Fatalf("content = %#v, want pong", out.Choices[0].Message.Content)
	}
	if strings.Contains(string(encoded), `"candidates"`) {
		t.Fatal("native Gemini candidates leaked into the client body")
	}
}

func adapterTargetPath(t *testing.T, providerType, model, apiVersion string) (string, error) {
	t.Helper()
	registry := NewAdapterRegistry()
	adapter, err := registry.Get(providerType)
	if err != nil {
		return "", err
	}
	_, path, err := adapter.TransformRequest(
		[]byte(`{"model":"`+model+`","messages":[{"role":"user","content":"hi"}]}`),
		model,
		apiVersion,
	)
	return path, err
}
