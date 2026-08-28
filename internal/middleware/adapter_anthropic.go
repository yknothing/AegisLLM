package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/model"
)

// AnthropicAdapter converts OpenAI chat completions to the Messages API.
type AnthropicAdapter struct{}

func (a *AnthropicAdapter) Name() string { return gatewayconst.ProviderTypeAnthropic }

func (a *AnthropicAdapter) TransformRequest(body []byte, modelName, apiVersion string) ([]byte, string, error) {
	var req model.ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", err
	}
	systemText, messages, err := splitOpenAIMessages(req.Messages)
	if err != nil {
		return nil, "", err
	}
	maxTokens := gatewayconst.DefaultAnthropicMaxTokens
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTokens = *req.MaxTokens
	} else if req.MaxCompletionTokens != nil && *req.MaxCompletionTokens > 0 {
		maxTokens = *req.MaxCompletionTokens
	}
	if strings.TrimSpace(req.Model) != "" {
		modelName = req.Model
	}
	payload := anthropicRequest{
		Model:     modelName,
		Messages:  messages,
		MaxTokens: maxTokens,
		Stream:    req.Stream,
	}
	if systemText != "" {
		payload.System = systemText
	}
	if req.Temperature != nil {
		payload.Temperature = req.Temperature
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	return encoded, gatewayconst.PathAnthropicMessages, nil
}

func (a *AnthropicAdapter) TransformResponse(body []byte) ([]byte, error) {
	var native anthropicResponse
	if err := json.Unmarshal(body, &native); err != nil {
		return nil, err
	}
	text := joinAnthropicText(native.Content)
	out := model.ChatCompletionResponse{
		ID:      native.ID,
		Object:  gatewayconst.OpenAIObjectChatCompletion,
		Created: time.Now().Unix(),
		Model:   native.Model,
		Choices: []model.Choice{{
			Index:        0,
			Message:      model.Message{Role: gatewayconst.MessageRoleAssistant, Content: text},
			FinishReason: mapAnthropicStop(native.StopReason),
		}},
		Usage: &model.Usage{
			PromptTokens:     native.Usage.InputTokens,
			CompletionTokens: native.Usage.OutputTokens,
			TotalTokens:      native.Usage.InputTokens + native.Usage.OutputTokens,
		},
	}
	return json.Marshal(out)
}

func (a *AnthropicAdapter) TransformStreamLine(line string) (string, bool, error) {
	if line == "" || strings.HasPrefix(line, "event:") {
		return "", true, nil
	}
	if !strings.HasPrefix(line, "data: ") {
		return line, false, nil
	}
	raw := strings.TrimPrefix(line, "data: ")
	if raw == "[DONE]" {
		return line, false, nil
	}
	var event anthropicStreamEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return "", false, err
	}
	chunk, skip, err := anthropicEventToChunk(event)
	if err != nil || skip {
		return "", skip, err
	}
	encoded, err := json.Marshal(chunk)
	if err != nil {
		return "", false, err
	}
	return "data: " + string(encoded), false, nil
}

func (a *AnthropicAdapter) SupportsStreaming() bool { return true }
func (a *AnthropicAdapter) AuthHeader() (string, string) {
	return gatewayconst.AuthHeaderAnthropicKey, ""
}
func (a *AnthropicAdapter) ExtraHeaders() map[string]string {
	return map[string]string{gatewayconst.AnthropicVersionHeader: gatewayconst.AnthropicAPIVersion}
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Stream      bool               `json:"stream,omitempty"`
	Temperature *float64           `json:"temperature,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	ID         string             `json:"id"`
	Model      string             `json:"model"`
	StopReason string             `json:"stop_reason"`
	Content    []anthropicContent `json:"content"`
	Usage      anthropicUsage     `json:"usage"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicStreamEvent struct {
	Type  string `json:"type"`
	Delta struct {
		Type       string `json:"type"`
		Text       string `json:"text"`
		StopReason string `json:"stop_reason"`
	} `json:"delta"`
	Message struct {
		ID    string `json:"id"`
		Model string `json:"model"`
	} `json:"message"`
}

func splitOpenAIMessages(messages []model.Message) (string, []anthropicMessage, error) {
	var systemParts []string
	converted := make([]anthropicMessage, 0, len(messages))
	for _, message := range messages {
		text, err := messageText(message.Content)
		if err != nil {
			return "", nil, err
		}
		switch message.Role {
		case gatewayconst.MessageRoleSystem:
			systemParts = append(systemParts, text)
		case gatewayconst.MessageRoleUser, gatewayconst.MessageRoleAssistant:
			converted = append(converted, anthropicMessage{Role: message.Role, Content: text})
		default:
			return "", nil, fmt.Errorf("unsupported message role")
		}
	}
	return strings.Join(systemParts, "\n"), converted, nil
}

func messageText(content interface{}) (string, error) {
	switch value := content.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	case []interface{}:
		var parts []string
		for _, part := range value {
			encoded, err := json.Marshal(part)
			if err != nil {
				return "", err
			}
			var typed model.ContentPart
			if err := json.Unmarshal(encoded, &typed); err != nil {
				return "", err
			}
			if typed.Type == "text" {
				parts = append(parts, typed.Text)
			}
		}
		return strings.Join(parts, ""), nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", err
		}
		var typed []model.ContentPart
		if err := json.Unmarshal(encoded, &typed); err == nil {
			var parts []string
			for _, part := range typed {
				if part.Type == "text" {
					parts = append(parts, part.Text)
				}
			}
			return strings.Join(parts, ""), nil
		}
		return string(bytes.TrimSpace(encoded)), nil
	}
}

func joinAnthropicText(parts []anthropicContent) string {
	var texts []string
	for _, part := range parts {
		if part.Type == "text" || part.Type == "" {
			texts = append(texts, part.Text)
		}
	}
	return strings.Join(texts, "")
}

func mapAnthropicStop(reason string) string {
	switch reason {
	case gatewayconst.AnthropicStopMaxTok:
		return gatewayconst.FinishReasonLength
	default:
		return gatewayconst.FinishReasonStop
	}
}

func anthropicEventToChunk(event anthropicStreamEvent) (model.ChatCompletionChunk, bool, error) {
	chunk := model.ChatCompletionChunk{
		ID:      event.Message.ID,
		Object:  gatewayconst.OpenAIObjectChatChunk,
		Created: time.Now().Unix(),
		Model:   event.Message.Model,
		Choices: []model.ChunkChoice{{Index: 0}},
	}
	switch event.Type {
	case "content_block_delta":
		chunk.Choices[0].Delta.Content = event.Delta.Text
		return chunk, false, nil
	case "message_delta":
		if event.Delta.StopReason != "" {
			chunk.Choices[0].FinishReason = mapAnthropicStop(event.Delta.StopReason)
			return chunk, false, nil
		}
		return chunk, true, nil
	case "message_start", "content_block_start", "content_block_stop", "message_stop", "ping":
		return chunk, true, nil
	default:
		return chunk, true, nil
	}
}
