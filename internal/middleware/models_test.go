package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/server"
)

func TestModelsListIntersectsKeyAndCatalog(t *testing.T) {
	handler := ModelsList([]ProviderChannel{
		{ID: "openai-primary", Enabled: true, Models: []string{"gpt-4o-mini", "gpt-4o"}},
		{ID: "deepseek-primary", Enabled: true, Models: []string{"deepseek-v3"}},
	})
	ctx := &server.RequestContext{
		Writer:      httptest.NewRecorder(),
		Request:     httptest.NewRequest(http.MethodGet, gatewayconst.PathModels, nil),
		Permissions: []string{"gpt-4o-mini", "deepseek-v3"},
	}
	handler(ctx, func() {})
	if ctx.IsAborted() {
		t.Fatal("ModelsList aborted an authorized catalog query")
	}
	recorder := ctx.Writer.(*httptest.ResponseRecorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var payload struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Object != gatewayconst.OpenAIObjectList || len(payload.Data) != 2 {
		t.Fatalf("payload = %+v, want two permitted models", payload)
	}
	if payload.Data[0].ID != "deepseek-v3" || payload.Data[1].ID != "gpt-4o-mini" {
		t.Fatalf("ids = %v, want sorted intersection", payload.Data)
	}
}
