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
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		Issuer:    "aegis",
	})

	if _, err := validateToken(token, key, "aegis"); err == nil {
		t.Fatal("validateToken accepted an expired token")
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
