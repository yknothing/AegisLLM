package runtime

import (
	"testing"

	"github.com/yknothing/AegisLLM/internal/config"
)

func TestProviderRuntimeAcceptsExplicitEgressDomains(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Name:     "OpenAI Primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}

	channels, keyMapping, providerTypes, err := providerRuntime(cfg)
	if err != nil {
		t.Fatalf("providerRuntime returned error: %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("channels len = %d, want 1", len(channels))
	}
	if keyMapping["openai-primary"] != "openai-key-1" {
		t.Fatalf("key mapping was not populated")
	}
	if providerTypes["openai-primary"] != "openai" {
		t.Fatalf("provider type was not populated")
	}
}

func TestProviderRuntimeRejectsHTTPProvider(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "unsafe",
				Type:     "openai",
				BaseURL:  "http://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.openai.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted a non-HTTPS provider")
	}
}

func TestProviderRuntimeRequiresExplicitEgressAllowlist(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "openai-primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				APIKeyID: "openai-key-1",
				Models:   []string{"gpt-4o-mini"},
				Enabled:  true,
			},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted an empty egress allowlist")
	}
}

func TestProviderRuntimeRejectsUnsupportedProviderType(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				ID:       "anthropic-primary",
				Type:     "anthropic",
				BaseURL:  "https://api.anthropic.com",
				APIKeyID: "anthropic-key-1",
				Models:   []string{"claude-sonnet-4-20250514"},
				Enabled:  true,
			},
		},
		Egress: config.EgressConfig{
			AllowedDomains: []string{"api.anthropic.com"},
		},
	}

	if _, _, _, err := providerRuntime(cfg); err == nil {
		t.Fatal("providerRuntime accepted an unsupported provider type")
	}
}
