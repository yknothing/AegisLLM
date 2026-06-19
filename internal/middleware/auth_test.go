package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidateTokenHS256(t *testing.T) {
	key := []byte("test-signing-key")
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		Subject:   "user_1",
		Models:    []string{"gpt-4o-mini"},
		KeySource: "pool",
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	claims, err := validateToken(token, key, "aegis")
	if err != nil {
		t.Fatalf("validateToken returned error: %v", err)
	}
	if claims.KeyID != "vk_test" {
		t.Fatalf("key id = %q, want vk_test", claims.KeyID)
	}
}

func TestValidateTokenRejectsBadSignature(t *testing.T) {
	token := signTestToken(t, []byte("correct-key"), VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, []byte("wrong-key"), "aegis"); err == nil {
		t.Fatal("validateToken accepted a token with the wrong signing key")
	}
}

func TestValidateTokenRejectsExpired(t *testing.T) {
	key := []byte("test-signing-key")
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis"); err == nil {
		t.Fatal("validateToken accepted an expired token")
	}
}

func TestValidateTokenRejectsReservedBudgetAndTPMClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims VirtualKeyClaims
	}{
		{
			name: "budget",
			claims: VirtualKeyClaims{
				BudgetUSD: 10,
			},
		},
		{
			name: "tpm",
			claims: VirtualKeyClaims{
				MaxTPM: 1000,
			},
		},
	}

	key := []byte("test-signing-key")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := tt.claims
			claims.KeyID = "vk_test"
			claims.KeySource = "pool"
			claims.Models = []string{"gpt-4o-mini"}
			claims.IssuedAt = time.Now().Add(-time.Minute).Unix()
			claims.ExpiresAt = time.Now().Add(time.Hour).Unix()
			claims.Issuer = "aegis"

			token := signTestToken(t, key, claims)
			if _, err := validateToken(token, key, "aegis"); err == nil {
				t.Fatalf("validateToken accepted reserved %s claim", tt.name)
			}
		})
	}
}

func TestValidateTokenRejectsNegativeLimitClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims VirtualKeyClaims
	}{
		{
			name: "rpm",
			claims: VirtualKeyClaims{
				MaxRPM: -1,
			},
		},
		{
			name: "budget",
			claims: VirtualKeyClaims{
				BudgetUSD: -1,
			},
		},
		{
			name: "tpm",
			claims: VirtualKeyClaims{
				MaxTPM: -1,
			},
		},
	}

	key := []byte("test-signing-key")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := tt.claims
			claims.KeyID = "vk_test"
			claims.KeySource = "pool"
			claims.Models = []string{"gpt-4o-mini"}
			claims.IssuedAt = time.Now().Add(-time.Minute).Unix()
			claims.ExpiresAt = time.Now().Add(time.Hour).Unix()
			claims.Issuer = "aegis"

			token := signTestToken(t, key, claims)
			if _, err := validateToken(token, key, "aegis"); err == nil {
				t.Fatalf("validateToken accepted negative %s claim", tt.name)
			}
		})
	}
}

func TestValidateTokenRejectsMissingModelPermissions(t *testing.T) {
	key := []byte("test-signing-key")
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis"); err == nil || !strings.Contains(err.Error(), "missing model permissions") {
		t.Fatalf("validateToken error = %v, want missing model permissions", err)
	}
}

func TestValidateTokenAcceptsExplicitWildcardModelPermission(t *testing.T) {
	key := []byte("test-signing-key")
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"*"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis"); err != nil {
		t.Fatalf("validateToken rejected wildcard model permission: %v", err)
	}
}

func TestIsModelAllowedFailsClosedForEmptyPermissions(t *testing.T) {
	if isModelAllowed("gpt-4o-mini", nil) {
		t.Fatal("isModelAllowed accepted an empty permission list")
	}
}

func signTestToken(t *testing.T, key []byte, claims VirtualKeyClaims) string {
	t.Helper()

	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	segments := []string{
		base64.RawURLEncoding.EncodeToString(headerJSON),
		base64.RawURLEncoding.EncodeToString(claimsJSON),
	}
	signingInput := strings.Join(segments, ".")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	segments = append(segments, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return strings.Join(segments, ".")
}
