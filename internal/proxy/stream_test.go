package proxy

import (
	"net/http"
	"testing"
)

func TestValidateEgressRequiresAllowlist(t *testing.T) {
	engine := NewEngine(StreamConfig{})

	if err := engine.validateEgress("https://api.openai.com/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted a target with no allowlist")
	}
}

func TestValidateEgressMatchesNormalizedHost(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("https://api.openai.com/v1/chat/completions"); err != nil {
		t.Fatalf("validateEgress rejected allowed host: %v", err)
	}
}

func TestValidateEgressRejectsSubstringBypass(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("https://api.openai.com.evil.example/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted substring host bypass")
	}
}

func TestValidateEgressRejectsNonHTTPS(t *testing.T) {
	engine := NewEngine(StreamConfig{
		AllowedDomains: []string{"api.openai.com"},
	})

	if err := engine.validateEgress("http://api.openai.com/v1/chat/completions"); err == nil {
		t.Fatal("validateEgress accepted non-HTTPS egress")
	}
}

func TestCopyHeadersStripsSensitiveForwardingHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("Authorization", "Bearer client")
	src.Set("X-Api-Key", "client-key")
	src.Set("X-Admin-Token", "admin-token")
	src.Set("X-Forwarded-For", "203.0.113.1")
	src.Set("X-Forwarded-Host", "internal.example")
	src.Set("X-Forwarded-Proto", "http")
	src.Set("Forwarded", "for=203.0.113.1")
	src.Set("User-Agent", "aegis-test")

	dst := http.Header{}
	copyHeaders(dst, src)

	for _, header := range []string{
		"Authorization",
		"X-Api-Key",
		"X-Admin-Token",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Forwarded",
	} {
		if got := dst.Get(header); got != "" {
			t.Fatalf("copyHeaders forwarded sensitive header %s=%q", header, got)
		}
	}
	if got := dst.Get("User-Agent"); got != "aegis-test" {
		t.Fatalf("copyHeaders stripped safe User-Agent header: %q", got)
	}
}
