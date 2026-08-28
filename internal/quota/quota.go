// Package quota enforces in-memory virtual-key budgets and records USD cost.
//
// SECURITY:
//   - Exhausted budgets fail closed before provider egress.
//   - Cost figures are non-sensitive metadata and may be logged.
//   - Unknown models fail closed when quota is enabled; there is no silent
//     default price.
package quota

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
)

// Common errors for quota operations.
var (
	ErrBudgetExhausted      = errors.New("quota: monthly budget exhausted")
	ErrKeyNotFound          = errors.New("quota: virtual key not found")
	ErrUnknownModelPricing  = errors.New("quota: model pricing is not configured")
)

// Manager handles budget tracking and cost calculation.
type Manager struct {
	store          Store
	pricing        *PricingTable
	defaultBudget  float64
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
		{Model: "gpt-4o", InputPerMillion: priceGPT4oInput, OutputPerMillion: priceGPT4oOutput},
		{Model: "gpt-4o-mini", InputPerMillion: priceGPT4oMiniInput, OutputPerMillion: priceGPT4oMiniOutput},
		{Model: "gpt-4.1", InputPerMillion: priceGPT41Input, OutputPerMillion: priceGPT41Output},
		{Model: "claude-sonnet-4-20250514", InputPerMillion: priceClaudeSonnetInput, OutputPerMillion: priceClaudeSonnetOutput},
		{Model: "claude-haiku-3-5", InputPerMillion: priceClaudeHaikuInput, OutputPerMillion: priceClaudeHaikuOutput},
		{Model: "gemini-2.5-pro", InputPerMillion: priceGeminiProInput, OutputPerMillion: priceGeminiProOutput},
		{Model: "gemini-2.5-flash", InputPerMillion: priceGeminiFlashInput, OutputPerMillion: priceGeminiFlashOutput},
		{Model: "deepseek-v3", InputPerMillion: priceDeepSeekV3Input, OutputPerMillion: priceDeepSeekV3Output},
		{Model: "deepseek-r1", InputPerMillion: priceDeepSeekR1Input, OutputPerMillion: priceDeepSeekR1Output},
	}

	for _, p := range defaults {
		pt.models[p.Model] = p
	}

	return pt
}

const (
	priceGPT4oInput         = 2.50
	priceGPT4oOutput        = 10.00
	priceGPT4oMiniInput     = 0.15
	priceGPT4oMiniOutput    = 0.60
	priceGPT41Input         = 2.00
	priceGPT41Output        = 8.00
	priceClaudeSonnetInput  = 3.00
	priceClaudeSonnetOutput = 15.00
	priceClaudeHaikuInput   = 0.80
	priceClaudeHaikuOutput  = 4.00
	priceGeminiProInput     = 1.25
	priceGeminiProOutput    = 10.00
	priceGeminiFlashInput   = 0.15
	priceGeminiFlashOutput  = 0.60
	priceDeepSeekV3Input    = 0.27
	priceDeepSeekV3Output   = 1.10
	priceDeepSeekR1Input    = 0.55
	priceDeepSeekR1Output   = 2.19
)

// CalculateCost computes the cost for a given request.
func (pt *PricingTable) CalculateCost(model string, inputTokens, outputTokens int) (float64, error) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	pricing, ok := pt.models[model]
	if !ok {
		return 0, ErrUnknownModelPricing
	}

	inputCost := float64(inputTokens) / gatewayconst.TokensPerMillion * pricing.InputPerMillion
	outputCost := float64(outputTokens) / gatewayconst.TokensPerMillion * pricing.OutputPerMillion
	return inputCost + outputCost, nil
}

// Set replaces or adds a model price.
func (pt *PricingTable) Set(pricing ModelPricing) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.models[pricing.Model] = pricing
}

// RequireModels fails closed when any model lacks a price row.
func (pt *PricingTable) RequireModels(models []string) error {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	for _, model := range models {
		if _, ok := pt.models[model]; !ok {
			return ErrUnknownModelPricing
		}
	}
	return nil
}

// NewManager creates a new quota manager.
func NewManager(store Store, defaultBudget float64) *Manager {
	return &Manager{
		store:         store,
		pricing:       NewPricingTable(),
		defaultBudget: defaultBudget,
	}
}

// Pricing returns the mutable pricing table for startup overlays.
func (m *Manager) Pricing() *PricingTable {
	return m.pricing
}

// CheckBudget verifies that a virtual key has remaining budget.
func (m *Manager) CheckBudget(ctx context.Context, keyID string, keyBudget float64) error {
	budget, err := m.effectiveBudget(ctx, keyID, keyBudget)
	if err != nil {
		return err
	}
	if budget <= 0 {
		return nil
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

func (m *Manager) effectiveBudget(ctx context.Context, keyID string, keyBudget float64) (float64, error) {
	if keyBudget > 0 {
		return keyBudget, nil
	}
	stored, err := m.store.GetBudget(ctx, keyID)
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return 0, err
	}
	if stored > 0 {
		return stored, nil
	}
	return m.defaultBudget, nil
}

// RecordRequest records the cost of a completed request.
func (m *Manager) RecordRequest(ctx context.Context, keyID, model, provider string, inputTokens, outputTokens int) error {
	cost, err := m.pricing.CalculateCost(model, inputTokens, outputTokens)
	if err != nil {
		return err
	}
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

// UsageOf returns current usage for admin queries.
func (m *Manager) UsageOf(ctx context.Context, keyID string) (*Usage, error) {
	return m.store.GetUsage(ctx, keyID)
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
		return 0, nil
	}
	return b, nil
}

func (s *MemoryStore) SetBudget(ctx context.Context, keyID string, budgetUSD float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.budgets[keyID] = budgetUSD
	return nil
}
