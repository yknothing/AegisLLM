// Package virtualkey owns the Aegis HS256 virtual-key claims, issuance, and
// validation contract.
//
// SECURITY PROPERTIES:
//   - Only HS256 is accepted and signatures use constant-time comparison.
//   - Issuance enforces the same lifetime and reserved-claim rules as
//     validation.
//   - Signing keys are caller-owned byte slices and are never logged or copied
//     into long-lived package state.
package virtualkey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MinSigningKeyBytes = 32
	ClockSkew          = 60 * time.Second
	KeySourcePool      = "pool"
	keySourceBYOK      = "byok"
)

// Claims represents the JWT payload for an Aegis virtual key.
type Claims struct {
	KeyID          string   `json:"kid"`
	Subject        string   `json:"sub"`
	Models         []string `json:"models"`
	MaxRPM         int      `json:"rpm"`
	MaxTPM         int      `json:"tpm"`
	MaxConcurrency int      `json:"max_concurrency"`
	BudgetUSD      float64  `json:"budget"`
	KeySource      string   `json:"key_source"`
	BYOKKeyID      string   `json:"byok_key_id,omitempty"`
	PoolGroup      string   `json:"pool_group,omitempty"`
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
	Issuer         string   `json:"iss"`
}

// IssueOptions contains supported v0.2.1 pool-token issuance inputs.
type IssueOptions struct {
	KeyID          string
	Subject        string
	Models         []string
	MaxRPM         int
	MaxConcurrency int
	PoolGroup      string
	TTL            time.Duration
	MaxTTL         time.Duration
	Issuer         string
	Now            time.Time
}

// Issue creates a pool virtual key and returns the exact signed claims.
func Issue(signingKey []byte, opts IssueOptions) (string, *Claims, error) {
	if len(signingKey) < MinSigningKeyBytes {
		return "", nil, fmt.Errorf("signing key must be at least %d bytes", MinSigningKeyBytes)
	}
	if strings.TrimSpace(opts.Subject) == "" {
		return "", nil, errors.New("virtual key subject must not be empty")
	}
	if strings.TrimSpace(opts.Issuer) == "" {
		return "", nil, errors.New("virtual key issuer must not be empty")
	}
	models, err := normalizeModels(opts.Models)
	if err != nil {
		return "", nil, err
	}
	if opts.MaxRPM < 0 || opts.MaxConcurrency < 0 {
		return "", nil, errors.New("virtual key limits must not be negative")
	}
	if opts.MaxTTL <= 0 {
		return "", nil, errors.New("configured maximum token lifetime must be positive")
	}
	if opts.TTL == 0 {
		opts.TTL = opts.MaxTTL
	}
	if opts.TTL < time.Second {
		return "", nil, errors.New("virtual key lifetime must be at least one second")
	}
	if opts.TTL > opts.MaxTTL {
		return "", nil, errors.New("virtual key lifetime exceeds configured maximum")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	keyID := strings.TrimSpace(opts.KeyID)
	if keyID == "" {
		keyID, err = generateKeyID()
		if err != nil {
			return "", nil, err
		}
	}
	claims := &Claims{
		KeyID:          keyID,
		Subject:        strings.TrimSpace(opts.Subject),
		Models:         models,
		MaxRPM:         opts.MaxRPM,
		MaxConcurrency: opts.MaxConcurrency,
		KeySource:      KeySourcePool,
		PoolGroup:      strings.TrimSpace(opts.PoolGroup),
		IssuedAt:       opts.Now.UTC().Unix(),
		ExpiresAt:      opts.Now.UTC().Add(opts.TTL).Unix(),
		Issuer:         strings.TrimSpace(opts.Issuer),
	}
	token, err := sign(signingKey, claims)
	if err != nil {
		return "", nil, err
	}
	return token, claims, nil
}

// Validate verifies a virtual key against the current time.
func Validate(token string, signingKey []byte, expectedIssuer string, maxTokenTTL time.Duration) (*Claims, error) {
	return ValidateAt(token, signingKey, expectedIssuer, maxTokenTTL, time.Now())
}

// ValidateAt verifies a virtual key at an explicit time for deterministic
// tests and offline issuance verification.
func ValidateAt(token string, signingKey []byte, expectedIssuer string, maxTokenTTL time.Duration, now time.Time) (*Claims, error) {
	if len(signingKey) < MinSigningKeyBytes {
		return nil, fmt.Errorf("signing key must be at least %d bytes", MinSigningKeyBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid token header JSON: %w", err)
	}
	if header.Alg != "HS256" {
		return nil, errors.New("unsupported signing algorithm")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid token signature: %w", err)
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if subtle.ConstantTimeCompare(signature, mac.Sum(nil)) != 1 {
		return nil, errors.New("invalid signature")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid token claims: %w", err)
	}
	if err := validateClaims(claims, expectedIssuer, maxTokenTTL, now); err != nil {
		return nil, err
	}
	return &claims, nil
}

func sign(signingKey []byte, claims *Claims) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("encoding virtual key header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding virtual key claims: %w", err)
	}
	segments := []string{
		base64.RawURLEncoding.EncodeToString(headerJSON),
		base64.RawURLEncoding.EncodeToString(claimsJSON),
	}
	signingInput := strings.Join(segments, ".")
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(signingInput))
	segments = append(segments, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return strings.Join(segments, "."), nil
}

func validateClaims(claims Claims, expectedIssuer string, maxTokenTTL time.Duration, now time.Time) error {
	nowUnix := now.Unix()
	if claims.KeyID == "" {
		return errors.New("missing key id")
	}
	if len(claims.Models) == 0 {
		return errors.New("missing model permissions")
	}
	if claims.ExpiresAt <= nowUnix {
		return errors.New("token expired")
	}
	if claims.IssuedAt > nowUnix+int64(ClockSkew.Seconds()) {
		return errors.New("token issued in the future")
	}
	if maxTokenTTL > 0 {
		if claims.IssuedAt <= 0 {
			return errors.New("missing issued-at claim")
		}
		if claims.ExpiresAt <= claims.IssuedAt {
			return errors.New("token expires before issued-at")
		}
		if time.Unix(claims.ExpiresAt, 0).Sub(time.Unix(claims.IssuedAt, 0)) > maxTokenTTL {
			return errors.New("token lifetime exceeds configured maximum")
		}
	}
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return errors.New("invalid issuer")
	}
	if claims.KeySource == "" {
		return errors.New("missing key source")
	}
	switch claims.KeySource {
	case KeySourcePool:
		if claims.BYOKKeyID != "" {
			return errors.New("byok_key_id is reserved for unsupported BYOK mode")
		}
	case keySourceBYOK:
		return errors.New("BYOK key source is not implemented")
	default:
		return errors.New("invalid key source")
	}
	if claims.MaxRPM < 0 || claims.BudgetUSD < 0 || claims.MaxTPM < 0 || claims.MaxConcurrency < 0 {
		return errors.New("virtual key limits must not be negative")
	}
	if claims.BudgetUSD > 0 {
		return errors.New("budget enforcement is not implemented")
	}
	if claims.MaxTPM > 0 {
		return errors.New("TPM enforcement is not implemented")
	}
	return nil
}

func normalizeModels(models []string) ([]string, error) {
	if len(models) == 0 {
		return nil, errors.New("virtual key models must not be empty")
	}
	normalized := make([]string, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" {
			return nil, errors.New("virtual key model must not be empty")
		}
		if _, exists := seen[model]; exists {
			continue
		}
		seen[model] = struct{}{}
		normalized = append(normalized, model)
	}
	return normalized, nil
}

func generateKeyID() (string, error) {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generating virtual key id: %w", err)
	}
	return "vk_" + base64.RawURLEncoding.EncodeToString(random), nil
}
