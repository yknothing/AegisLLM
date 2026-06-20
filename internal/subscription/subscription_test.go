package subscription

import (
	"strings"
	"testing"
)

func TestDefaultTemplatesOmitReservedBYOKTier(t *testing.T) {
	templates := DefaultTemplates()
	if _, ok := templates[TierBYOK]; ok {
		t.Fatal("DefaultTemplates exposed reserved BYOK tier")
	}
}

func TestDefaultTemplatesUsePoolKeySource(t *testing.T) {
	for tier, template := range DefaultTemplates() {
		if template.KeySource != "pool" {
			t.Fatalf("tier %q key source = %q, want pool", tier, template.KeySource)
		}
	}
}

func TestDefaultTemplatesUseRuntimeSupportedModelFamilies(t *testing.T) {
	for tier, template := range DefaultTemplates() {
		for _, model := range template.Models {
			if strings.Contains(model, "claude") || strings.Contains(model, "gemini") || model == "*" {
				t.Fatalf("tier %q exposed model %q before its provider adapter is enabled", tier, model)
			}
		}
	}
}
