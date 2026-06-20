package egress

import "testing"

func TestHostAllowedRequiresExactHostByDefault(t *testing.T) {
	allowed := []string{"api.openai.com"}

	if !HostAllowed("api.openai.com", allowed) {
		t.Fatal("HostAllowed rejected exact allowed host")
	}
	if HostAllowed("tenant.api.openai.com", allowed) {
		t.Fatal("HostAllowed accepted implicit subdomain without wildcard")
	}
}

func TestHostAllowedSupportsExplicitWildcardSubdomains(t *testing.T) {
	allowed := []string{"*.openai.com"}

	if !HostAllowed("api.openai.com", allowed) {
		t.Fatal("HostAllowed rejected explicit wildcard subdomain")
	}
	if !HostAllowed("tenant.api.openai.com", allowed) {
		t.Fatal("HostAllowed rejected nested explicit wildcard subdomain")
	}
	if HostAllowed("openai.com", allowed) {
		t.Fatal("HostAllowed accepted wildcard apex host")
	}
}

func TestHostAllowedNormalizesHostAndURLAllowlistEntries(t *testing.T) {
	allowed := []string{"https://API.OpenAI.com:443/path"}

	if !HostAllowed("API.OpenAI.com.", allowed) {
		t.Fatal("HostAllowed rejected normalized URL allowlist host")
	}
}

func TestHostAllowedRejectsSubstringBypass(t *testing.T) {
	allowed := []string{"api.openai.com"}

	if HostAllowed("api.openai.com.evil.example", allowed) {
		t.Fatal("HostAllowed accepted substring bypass")
	}
}
