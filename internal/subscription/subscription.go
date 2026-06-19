// Package subscription maps application subscription tiers to Aegis Virtual Key permissions.
//
// DESIGN:
//   - Defines permission templates for each tier (Free, Pro, Enterprise)
//   - Reserved for the planned admin API when issuing Virtual Keys
//   - Centralizes the business logic of "what does each tier get?"
//
// This package will bridge the gap between the app's billing system and
// Aegis's technical access control. Current runtime does not yet mount the
// admin API or enforce TPM/budget controls.
package subscription

import "time"

// Tier represents a subscription level.
type Tier string

const (
	TierFree       Tier = "free"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
	TierBYOK       Tier = "byok"
)

// Template defines the permissions and limits for a subscription tier.
type Template struct {
	Tier           Tier
	Models         []string      // Allowed models
	RPM            int           // Requests per minute (0 = unlimited)
	TPM            int           // Tokens per minute (0 = unlimited)
	MaxConcurrency int           // Max concurrent requests
	BudgetUSD      float64       // Monthly budget in USD (0 = unlimited)
	TokenExpiry    time.Duration // Virtual Key validity period
	KeySource      string        // "pool" or "byok"
}

// DefaultTemplates returns the standard tier configurations.
// Current runtime-compatible templates keep TPM and BudgetUSD at 0 because
// non-zero values are rejected until enforcement exists.
func DefaultTemplates() map[Tier]Template {
	return map[Tier]Template{
		TierFree: {
			Tier:           TierFree,
			Models:         []string{"gpt-4o-mini", "gemini-2.5-flash", "deepseek-v3"},
			RPM:            10,
			TPM:            0,
			MaxConcurrency: 2,
			BudgetUSD:      0,
			TokenExpiry:    30 * 24 * time.Hour, // 30 days
			KeySource:      "pool",
		},
		TierPro: {
			Tier:           TierPro,
			Models:         []string{"gpt-4o", "gpt-4o-mini", "claude-sonnet-4-20250514", "claude-haiku-3-5", "gemini-2.5-pro", "gemini-2.5-flash", "deepseek-v3", "deepseek-r1"},
			RPM:            60,
			TPM:            0,
			MaxConcurrency: 10,
			BudgetUSD:      0,
			TokenExpiry:    30 * 24 * time.Hour,
			KeySource:      "pool",
		},
		TierEnterprise: {
			Tier:           TierEnterprise,
			Models:         []string{"*"}, // All models
			RPM:            300,
			TPM:            0,
			MaxConcurrency: 50,
			BudgetUSD:      0,
			TokenExpiry:    90 * 24 * time.Hour,
			KeySource:      "pool",
		},
		TierBYOK: {
			Tier:           TierBYOK,
			Models:         []string{"*"},
			RPM:            0, // Unlimited
			TPM:            0,
			MaxConcurrency: 0,
			BudgetUSD:      0, // User's responsibility
			TokenExpiry:    365 * 24 * time.Hour,
			KeySource:      "byok",
		},
	}
}

// GetTemplate returns the template for a given tier.
// Returns the Free template if the tier is not recognized.
func GetTemplate(tier Tier) Template {
	templates := DefaultTemplates()
	if t, ok := templates[tier]; ok {
		return t
	}
	return templates[TierFree]
}
