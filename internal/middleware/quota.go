package middleware

import (
	"errors"
	"net/http"

	"github.com/yknothing/AegisLLM/internal/quota"
	"github.com/yknothing/AegisLLM/internal/server"
)

// Quota creates the budget middleware. It fails closed before egress and
// records USD cost after a completed attempt. Record failures are not
// returned to the client because the upstream response may already be committed.
func Quota(manager *quota.Manager) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		if manager == nil {
			ctx.Abort(http.StatusServiceUnavailable, []byte(`{"error":{"message":"quota service unavailable","type":"server_error"}}`))
			return
		}
		if err := manager.CheckBudget(ctx.Request.Context(), ctx.VirtualKeyID, ctx.Budget); err != nil {
			if errors.Is(err, quota.ErrBudgetExhausted) {
				ctx.Abort(http.StatusTooManyRequests, []byte(`{"error":{"message":"budget exhausted","type":"insufficient_quota"}}`))
				return
			}
			ctx.Abort(http.StatusServiceUnavailable, []byte(`{"error":{"message":"quota service unavailable","type":"server_error"}}`))
			return
		}

		next()

		if ctx.IsAborted() {
			return
		}
		if ctx.StatusCode >= http.StatusBadRequest {
			return
		}
		_ = manager.RecordRequest(
			ctx.Request.Context(),
			ctx.VirtualKeyID,
			ctx.Model,
			ctx.ProviderID,
			ctx.InputTokens,
			ctx.OutputTokens,
		)
	}
}
