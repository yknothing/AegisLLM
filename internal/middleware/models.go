package middleware

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/server"
)

// ModelsList is the terminal middleware for GET /v1/models.
// It returns the intersection of virtual-key permissions and configured models.
func ModelsList(channels []ProviderChannel) server.Middleware {
	catalog := make(map[string]string)
	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}
		for _, model := range channel.Models {
			if _, exists := catalog[model]; !exists {
				catalog[model] = channel.ID
			}
		}
	}

	return func(ctx *server.RequestContext, next func()) {
		ids := make([]string, 0, len(catalog))
		for model := range catalog {
			if isModelAllowed(model, ctx.Permissions) {
				ids = append(ids, model)
			}
		}
		sort.Strings(ids)

		type modelObject struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		}
		payload := struct {
			Object string        `json:"object"`
			Data   []modelObject `json:"data"`
		}{
			Object: gatewayconst.OpenAIObjectList,
			Data:   make([]modelObject, 0, len(ids)),
		}
		for _, id := range ids {
			payload.Data = append(payload.Data, modelObject{
				ID:      id,
				Object:  gatewayconst.OpenAIObjectModel,
				OwnedBy: catalog[id],
			})
		}
		body, err := json.Marshal(payload)
		if err != nil {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"failed to encode model list","type":"server_error"}}`))
			return
		}
		ctx.Writer.Header().Set("Content-Type", gatewayconst.JSONContentType)
		ctx.Writer.WriteHeader(http.StatusOK)
		_, _ = ctx.Writer.Write(body)
	}
}
