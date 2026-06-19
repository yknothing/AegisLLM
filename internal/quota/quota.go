// Package quota implements budget management and cost tracking for Aegis.
//
// DESIGN:
//   - Hierarchical budget model: Organization → Team → Virtual Key
//   - Real-time cost calculation based on provider pricing tables
//   - Pre-request budget check (reject if insufficient) and post-request deduction
//   - Supports both hard limits (reject) and soft limits (alert)
//
// SECURITY:
//   - Budget exhaustion prevents runaway costs from compromised keys
//   - Cost data is non-sensitive metadata (safe to log and store)
package quota

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Common errors for quota operations.
var (
	ErrBudgetExhausted = errors.New("quota: monthly budget exhausted")
	ErrKeyNotFound     = errors.New("quota: virtual key not found")
)

// Manager handles budget tracking and cost calculation.
type Manager struct {
	mu      sync.RWMutex
	store   Store
	pricing *PricingTable
}

// Store is the persistence interface for quota data.
type Store interface {
	// GetUsage returns the current month's usage for a virtual key.
	GetUsage(ctx context.Context, keyID string) (*Usage, error)

	// RecordUsage adds a cost entry for a virtual key.
	RecordUsage(ctx context.Context, keyID string, entry UsageEntry) error

	// GetBudget returns the configured budget for a virtual key.
	GetBudget(ctx context.Context, keyID string) (float64, error)

	// SetBudget configures the monthly budget for a virtual key.
	SetBudget(ctx context.Context, keyID string, budgetUSD float64) error
}

// Usage represents accumulated usage for a billing period.
type Usage struct {
	KeyID        string
	PeriodStart  time.Time
	TotalCostUSD float64
	TotalTokens  int64
	RequestCount int64
}

// UsageEntry represents a single request's cost.
type UsageEntry struct {
	Timestamp    time.Time
	Model        string
	Provider     string
	InputTokens  int
	OutputTokens int
	CostUSD      float64
}

// PricingTable holds per-model pricing information.
type PricingTable struct {
	mu     sync.RWMutex
	models map[string]ModelPricing
}

// ModelPricing defines the cost per token for a specific model.
type ModelPricing struct {
	Model            string
	InputPerMillion  float64 // USD per 1M input tokens
	OutputPerMillion float64 // USD per 1M output tokens
}

// NewPricingTable creates a pricing table with default model prices.
func NewPricingTable() *PricingTable {
	pt := &PricingTable{
		models: make(map[string]ModelPricing),
	}

	// Default pricing (as of 2026, should be configurable)
	defaults := []ModelPricing{
		{Model: "gpt-4o", InputPerMillion: 2.50, OutputPerMillion: 10.00},
		{Model: "gpt-4o-mini", InputPerMillion: 0.15, OutputPerMillion: 0.60},
		{Model: "gpt-4.1", InputPerMillion: 2.00, OutputPerMillion: 8.00},
		{Model: "claude-sonnet-4-20250514", InputPerMillion: 3.00, OutputPerMillion: 15.00},
		{Model: "claude-haiku-3-5", InputPerMillion: 0.80, OutputPerMillion: 4.00},
		{Model: "gemini-2.5-pro", InputPerMillion: 1.25, OutputPerMillion: 10.00},
		{Model: "gemini-2.5-flash", InputPerMillion: 0.15, OutputPerMillion: 0.60},
		{Model: "deepseek-v3", InputPerMillion: 0.27, OutputPerMillion: 1.10},
		{Model: "deepseek-r1", InputPerMillion: 0.55, OutputPerMillion: 2.19},
	}

	for _, p := range defaults {
		pt.models[p.Model] = p
	}

	return pt
}

// CalculateCost computes the cost for a given request.
func (pt *PricingTable) CalculateCost(model string, inputTokens, outputTokens int) float64 {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	pricing, ok := pt.models[model]
	if !ok {
		// Unknown model: use a conservative default
		pricing = ModelPricing{InputPerMillion: 5.0, OutputPerMillion: 15.0}
	}

	inputCost := float64(inputTokens) / 1_000_000 * pricing.InputPerMillion
	outputCost := float64(outputTokens) / 1_000_000 * pricing.OutputPerMillion

	return inputCost + outputCost
}

// NewManager creates a new quota manager.
func NewManager(store Store) *Manager {
	return &Manager{
		store:   store,
		pricing: NewPricingTable(),
	}
}

// CheckBudget verifies that a virtual key has remaining budget.
// Called BEFORE proxying the request.
func (m *Manager) CheckBudget(ctx context.Context, keyID string) error {
	budget, err := m.store.GetBudget(ctx, keyID)
	if err != nil {
		return err
	}

	usage, err := m.store.GetUsage(ctx, keyID)
	if err != nil {
		return err
	}

	if usage.TotalCostUSD >= budget {
		return ErrBudgetExhausted
	}

	return nil
}

// RecordRequest records the cost of a completed request.
// Called AFTER the proxy returns successfully.
func (m *Manager) RecordRequest(ctx context.Context, keyID, model, provider string, inputTokens, outputTokens int) error {
	cost := m.pricing.CalculateCost(model, inputTokens, outputTokens)

	entry := UsageEntry{
		Timestamp:    time.Now(),
		Model:        model,
		Provider:     provider,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		CostUSD:      cost,
	}

	return m.store.RecordUsage(ctx, keyID, entry)
}

// --- In-Memory Store (Standalone Mode) ---

// MemoryStore implements Store using in-memory maps.
type MemoryStore struct {
	mu      sync.RWMutex
	budgets map[string]float64
	usage   map[string]*Usage
}

// NewMemoryStore creates an in-memory quota store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		budgets: make(map[string]float64),
		usage:   make(map[string]*Usage),
	}
}

func (s *MemoryStore) GetUsage(ctx context.Context, keyID string) (*Usage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usage[keyID]
	if !ok {
		return &Usage{KeyID: keyID, PeriodStart: time.Now()}, nil
	}
	return u, nil
}

func (s *MemoryStore) RecordUsage(ctx context.Context, keyID string, entry UsageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usage[keyID]
	if !ok {
		u = &Usage{KeyID: keyID, PeriodStart: time.Now()}
		s.usage[keyID] = u
	}
	u.TotalCostUSD += entry.CostUSD
	u.TotalTokens += int64(entry.InputTokens + entry.OutputTokens)
	u.RequestCount++
	return nil
}

func (s *MemoryStore) GetBudget(ctx context.Context, keyID string) (float64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.budgets[keyID]
	if !ok {
		return 100.0, nil // Default budget
	}
	return b, nil
}

func (s *MemoryStore) SetBudget(ctx context.Context, keyID string, budgetUSD float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.budgets[keyID] = budgetUSD
	return nil
}
