package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yknothing/AegisLLM/internal/quota"
	"github.com/yknothing/AegisLLM/internal/server"
)

func TestQuotaFailsClosedWhenBudgetExhausted(t *testing.T) {
	store := quota.NewMemoryStore()
	if err := store.SetBudget(context.Background(), "vk_test", 1); err != nil {
		t.Fatalf("SetBudget: %v", err)
	}
	if err := store.RecordUsage(context.Background(), "vk_test", quota.UsageEntry{CostUSD: 1}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	manager := quota.NewManager(store, 0)
	ctx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
		Budget:       1,
	}
	calledNext := false
	Quota(manager)(ctx, func() { calledNext = true })
	if calledNext {
		t.Fatal("Quota called next after budget exhaustion")
	}
	if ctx.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", ctx.StatusCode)
	}
}

func TestQuotaAllowsRequestUnderBudget(t *testing.T) {
	manager := quota.NewManager(quota.NewMemoryStore(), 10)
	ctx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
		Budget:       10,
		Model:        "gpt-4o-mini",
		ProviderID:   "openai-primary",
	}
	calledNext := false
	Quota(manager)(ctx, func() {
		calledNext = true
		ctx.StatusCode = http.StatusOK
		ctx.InputTokens = 10
		ctx.OutputTokens = 5
	})
	if !calledNext || ctx.IsAborted() {
		t.Fatal("Quota rejected a request under budget")
	}
}
