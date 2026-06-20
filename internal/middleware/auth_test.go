package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/server"
)

var testSigningKey = []byte("0123456789abcdef0123456789abcdef")

const (
	testTokenMaxTTL           = 24 * time.Hour
	testTokenMaxConcurrency   = 3
	testContextMaxConcurrency = 2
)

func TestValidateTokenHS256(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:          "vk_test",
		Subject:        "user_1",
		Models:         []string{"gpt-4o-mini"},
		MaxConcurrency: testTokenMaxConcurrency,
		KeySource:      "pool",
		IssuedAt:       time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
		Issuer:         "aegis",
	})

	claims, err := validateToken(token, key, "aegis", testTokenMaxTTL)
	if err != nil {
		t.Fatalf("validateToken returned error: %v", err)
	}
	if claims.KeyID != "vk_test" {
		t.Fatalf("key id = %q, want vk_test", claims.KeyID)
	}
	if claims.MaxConcurrency != testTokenMaxConcurrency {
		t.Fatalf("max concurrency = %d, want %d", claims.MaxConcurrency, testTokenMaxConcurrency)
	}
}

func TestValidateTokenRejectsWeakSigningKey(t *testing.T) {
	token := signTestToken(t, []byte("weak-signing-key"), VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, []byte("weak-signing-key"), "aegis", testTokenMaxTTL); err == nil {
		t.Fatal("validateToken accepted a weak signing key")
	}
}

func TestValidateTokenRejectsBadSignature(t *testing.T) {
	token := signTestToken(t, []byte("correct-key-0123456789abcdef012345"), VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, []byte("wrong-key-0123456789abcdef01234567"), "aegis", testTokenMaxTTL); err == nil {
		t.Fatal("validateToken accepted a token with the wrong signing key")
	}
}

func TestValidateTokenRejectsExpired(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil {
		t.Fatal("validateToken accepted an expired token")
	}
}

func TestValidateTokenRejectsTokenLifetimeAboveConfiguredMax(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(48 * time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil {
		t.Fatal("validateToken accepted a token lifetime above auth.token_expiry")
	}
}

func TestValidateTokenRejectsMissingIssuedAtWhenMaxTTLConfigured(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"gpt-4o-mini"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil {
		t.Fatal("validateToken accepted missing iat with configured max TTL")
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

	key := testSigningKey
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
			if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil {
				t.Fatalf("validateToken accepted reserved %s claim", tt.name)
			}
		})
	}
}

func TestValidateTokenRejectsReservedBYOKKeySource(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: keySourceBYOK,
		BYOKKeyID: "user-456-openai",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil {
		t.Fatal("validateToken accepted reserved BYOK key source")
	}
}

func TestValidateTokenRejectsBYOKKeyIDInPoolToken(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: KeySourcePool,
		BYOKKeyID: "user-456-openai",
		Models:    []string{"gpt-4o-mini"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil {
		t.Fatal("validateToken accepted a pool token carrying byok_key_id")
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
		{
			name: "concurrency",
			claims: VirtualKeyClaims{
				MaxConcurrency: -1,
			},
		},
	}

	key := testSigningKey
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
			if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil {
				t.Fatalf("validateToken accepted negative %s claim", tt.name)
			}
		})
	}
}

func TestValidateTokenRejectsMissingModelPermissions(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err == nil || !strings.Contains(err.Error(), "missing model permissions") {
		t.Fatalf("validateToken error = %v, want missing model permissions", err)
	}
}

func TestValidateTokenAcceptsExplicitWildcardModelPermission(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:     "vk_test",
		KeySource: "pool",
		Models:    []string{"*"},
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis", testTokenMaxTTL); err != nil {
		t.Fatalf("validateToken rejected wildcard model permission: %v", err)
	}
}

func TestAuthFailureJSONUsesSingleClientFacingMessage(t *testing.T) {
	got := string(authFailureJSON())
	for _, forbidden := range []string{"missing authorization", "invalid authorization format", "revoked"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("auth failure JSON exposed %q: %s", forbidden, got)
		}
	}
	if !strings.Contains(got, "invalid or expired virtual key") {
		t.Fatalf("auth failure JSON = %s, want generic virtual key failure", got)
	}
}

func TestAuthPopulatesConcurrencyClaim(t *testing.T) {
	key := testSigningKey
	token := signTestToken(t, key, VirtualKeyClaims{
		KeyID:          "vk_test",
		KeySource:      "pool",
		Models:         []string{"gpt-4o-mini"},
		MaxConcurrency: testContextMaxConcurrency,
		IssuedAt:       time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
		Issuer:         "aegis",
	})
	ctx := &server.RequestContext{
		Request: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
	}
	ctx.Request.Header.Set("Authorization", "Bearer "+token)

	calledNext := false
	Auth(AuthConfig{
		SigningKey: key,
		Issuer:     "aegis",
		Expiry:     testTokenMaxTTL,
	})(ctx, func() {
		calledNext = true
	})

	if !calledNext {
		t.Fatal("Auth did not call next for a valid token")
	}
	if ctx.IsAborted() {
		t.Fatalf("Auth aborted valid token with status %d", ctx.StatusCode)
	}
	if ctx.MaxConcurrency != testContextMaxConcurrency {
		t.Fatalf("ctx.MaxConcurrency = %d, want %d", ctx.MaxConcurrency, testContextMaxConcurrency)
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
