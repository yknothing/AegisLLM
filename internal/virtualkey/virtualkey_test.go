package virtualkey

import (
	"strings"
	"testing"
	"time"
)

func TestIssueCreatesTokenAcceptedByProductionValidator(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0).UTC()
	token, claims, err := Issue(key, IssueOptions{
		Subject:        "operator-1",
		Models:         []string{"gpt-4o-mini"},
		MaxRPM:         20,
		MaxConcurrency: 3,
		TTL:            time.Hour,
		MaxTTL:         24 * time.Hour,
		Issuer:         "aegis",
		Now:            now,
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if !strings.HasPrefix(claims.KeyID, "vk_") {
		t.Fatalf("generated key id = %q, want vk_ prefix", claims.KeyID)
	}

	validated, err := ValidateAt(token, key, "aegis", 24*time.Hour, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ValidateAt issued token returned error: %v", err)
	}
	if validated.Subject != "operator-1" || validated.MaxRPM != 20 || validated.MaxConcurrency != 3 {
		t.Fatalf("validated claims = %+v, want issued values", validated)
	}
}

func TestIssueGeneratesDistinctKeyIDs(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	opts := IssueOptions{
		Subject: "operator-1",
		Models:  []string{"gpt-4o-mini"},
		TTL:     time.Hour,
		MaxTTL:  24 * time.Hour,
		Issuer:  "aegis",
		Now:     time.Unix(1_800_000_000, 0).UTC(),
	}
	_, first, err := Issue(key, opts)
	if err != nil {
		t.Fatalf("first Issue returned error: %v", err)
	}
	_, second, err := Issue(key, opts)
	if err != nil {
		t.Fatalf("second Issue returned error: %v", err)
	}
	if first.KeyID == second.KeyID {
		t.Fatalf("generated duplicate key id %q", first.KeyID)
	}
}

func TestIssueRejectsTTLAboveConfiguredMaximum(t *testing.T) {
	_, _, err := Issue([]byte("0123456789abcdef0123456789abcdef"), IssueOptions{
		Subject: "operator-1",
		Models:  []string{"gpt-4o-mini"},
		TTL:     48 * time.Hour,
		MaxTTL:  24 * time.Hour,
		Issuer:  "aegis",
		Now:     time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("Issue TTL error = %v, want maximum rejection", err)
	}
}

func TestIssueRejectsInvalidClaimsBeforeSigning(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*IssueOptions)
	}{
		{name: "empty subject", mutate: func(o *IssueOptions) { o.Subject = "" }},
		{name: "empty models", mutate: func(o *IssueOptions) { o.Models = nil }},
		{name: "negative rpm", mutate: func(o *IssueOptions) { o.MaxRPM = -1 }},
		{name: "negative concurrency", mutate: func(o *IssueOptions) { o.MaxConcurrency = -1 }},
		{name: "empty issuer", mutate: func(o *IssueOptions) { o.Issuer = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := IssueOptions{
				Subject: "operator-1",
				Models:  []string{"gpt-4o-mini"},
				TTL:     time.Hour,
				MaxTTL:  24 * time.Hour,
				Issuer:  "aegis",
				Now:     time.Now(),
			}
			tt.mutate(&opts)
			if _, _, err := Issue([]byte("0123456789abcdef0123456789abcdef"), opts); err == nil {
				t.Fatal("Issue accepted invalid claims")
			}
		})
	}
}
