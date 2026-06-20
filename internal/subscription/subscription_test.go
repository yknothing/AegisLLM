package subscription

import "testing"

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
