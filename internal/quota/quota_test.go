package quota

import (
	"context"
	"errors"
	"testing"
)

const (
	quotaTestKeyID            = "vk-quota-test"
	quotaTestUnknownModel     = "not-in-pricing-table"
	quotaTestKnownModel       = "gpt-4o-mini"
	quotaTestBudgetUSD        = 1.0
	quotaTestExhaustedCostUSD = 1.0
	quotaTestInputTokens      = 10
	quotaTestOutputTokens     = 5
	quotaTestProvider         = "openai"
)

func TestCalculateCostUnknownModelFailsClosed(t *testing.T) {
	_, err := NewPricingTable().CalculateCost(quotaTestUnknownModel, quotaTestInputTokens, quotaTestOutputTokens)
	if !errors.Is(err, ErrUnknownModelPricing) {
		t.Fatalf("CalculateCost error = %v, want %v", err, ErrUnknownModelPricing)
	}
}

func TestRequireModelsUnknownFailsClosed(t *testing.T) {
	err := NewPricingTable().RequireModels([]string{quotaTestKnownModel, quotaTestUnknownModel})
	if !errors.Is(err, ErrUnknownModelPricing) {
		t.Fatalf("RequireModels error = %v, want %v", err, ErrUnknownModelPricing)
	}
}

func TestRequireModelsKnownSucceeds(t *testing.T) {
	if err := NewPricingTable().RequireModels([]string{quotaTestKnownModel}); err != nil {
		t.Fatalf("RequireModels known model: %v", err)
	}
}

func TestCheckBudgetExhaustedFailsClosed(t *testing.T) {
	store := NewMemoryStore()
	manager := NewManager(store, 0)
	ctx := context.Background()
	if err := store.RecordUsage(ctx, quotaTestKeyID, UsageEntry{CostUSD: quotaTestExhaustedCostUSD}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	err := manager.CheckBudget(ctx, quotaTestKeyID, quotaTestBudgetUSD)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("CheckBudget error = %v, want %v", err, ErrBudgetExhausted)
	}
}

func TestCheckBudgetZeroMeansUnlimited(t *testing.T) {
	store := NewMemoryStore()
	manager := NewManager(store, 0)
	ctx := context.Background()
	if err := store.RecordUsage(ctx, quotaTestKeyID, UsageEntry{CostUSD: quotaTestExhaustedCostUSD}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if err := manager.CheckBudget(ctx, quotaTestKeyID, 0); err != nil {
		t.Fatalf("zero budget should be unlimited: %v", err)
	}
}

func TestRecordRequestUnknownModelFailsClosed(t *testing.T) {
	manager := NewManager(NewMemoryStore(), 0)
	err := manager.RecordRequest(context.Background(), quotaTestKeyID, quotaTestUnknownModel, quotaTestProvider, quotaTestInputTokens, quotaTestOutputTokens)
	if !errors.Is(err, ErrUnknownModelPricing) {
		t.Fatalf("RecordRequest error = %v, want %v", err, ErrUnknownModelPricing)
	}
}
