package middleware

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/model"
)

// GeminiAdapter converts OpenAI chat completions to generateContent.
type GeminiAdapter struct{}

func (a *GeminiAdapter) Name() string { return gatewayconst.ProviderTypeGoogle }

func (a *GeminiAdapter) TransformRequest(body []byte, modelName, apiVersion string) ([]byte, string, error) {
	var req model.ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(req.Model) != "" {
		modelName = req.Model
	}
	payload := geminiRequest{}
	for _, message := range req.Messages {
		text, err := messageText(message.Content)
		if err != nil {
			return nil, "", err
		}
		switch message.Role {
		case gatewayconst.MessageRoleSystem:
			payload.SystemInstruction = &geminiContent{Parts: []geminiPart{{Text: text}}}
		case gatewayconst.MessageRoleAssistant:
			payload.Contents = append(payload.Contents, geminiContent{
				Role:  gatewayconst.GeminiRoleModel,
				Parts: []geminiPart{{Text: text}},
			})
		default:
			payload.Contents = append(payload.Contents, geminiContent{
				Role:  gatewayconst.MessageRoleUser,
				Parts: []geminiPart{{Text: text}},
			})
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	suffix := gatewayconst.GeminiGenerateContent
	if req.Stream {
		suffix = gatewayconst.GeminiStreamGenerate
	}
	path := gatewayconst.GeminiGeneratePathPrefix + url.PathEscape(modelName) + suffix
	return encoded, path, nil
}

func (a *GeminiAdapter) TransformResponse(body []byte) ([]byte, error) {
	var native geminiResponse
	if err := json.Unmarshal(body, &native); err != nil {
		return nil, err
	}
	text := ""
	if len(native.Candidates) > 0 && len(native.Candidates[0].Content.Parts) > 0 {
		text = native.Candidates[0].Content.Parts[0].Text
	}
	out := model.ChatCompletionResponse{
		ID:     "gemini",
		Object: gatewayconst.OpenAIObjectChatCompletion,
		Model:  "",
		Choices: []model.Choice{{
			Index:        0,
			Message:      model.Message{Role: gatewayconst.MessageRoleAssistant, Content: text},
			FinishReason: gatewayconst.FinishReasonStop,
		}},
	}
	return json.Marshal(out)
}

func (a *GeminiAdapter) TransformStreamLine(line string) (string, bool, error) {
	return passthroughStreamLine(line)
}
func (a *GeminiAdapter) SupportsStreaming() bool { return true }
func (a *GeminiAdapter) AuthHeader() (string, string) {
	return gatewayconst.AuthHeaderGoogleAPIKey, ""
}
func (a *GeminiAdapter) ExtraHeaders() map[string]string { return nil }

type geminiRequest struct {
	Contents          []geminiContent `json:"contents"`
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResponse struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
}
