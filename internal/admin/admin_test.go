package admin

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/quota"
	"github.com/yknothing/AegisLLM/internal/revocation"
	"github.com/yknothing/AegisLLM/internal/utils"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
)

const adminTestToken = "admin-token"

func TestRegisterBYOKFailsClosed(t *testing.T) {
	kms := &recordingKMS{}
	handler := NewHandler(kms, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte(adminTestToken))

	req := httptest.NewRequest(http.MethodPost, "/admin/keys/byok", strings.NewReader(`{"user_id":"u1","provider":"openai","api_key":"sk-test"}`))
	req.Header.Set(adminTokenHeader, adminTestToken)
	rec := httptest.NewRecorder()

	handler.authMiddleware(handler.registerBYOK)(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
	if kms.storeCalls != 0 {
		t.Fatalf("StoreKey calls = %d, want 0", kms.storeCalls)
	}
}

func TestAdminAuthRejectsFailuresWithGenericMessage(t *testing.T) {
	handler := NewHandler(&recordingKMS{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte(adminTestToken))

	tests := []struct {
		name  string
		token string
	}{
		{name: "missing"},
		{name: "wrong same length", token: "wrong-token"},
		{name: "wrong short", token: "bad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/keys/byok", strings.NewReader(`{}`))
			if tt.token != "" {
				req.Header.Set(adminTokenHeader, tt.token)
			}
			rec := httptest.NewRecorder()

			handler.authMiddleware(handler.registerBYOK)(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			body := rec.Body.String()
			if !strings.Contains(body, adminAuthFailedError) {
				t.Fatalf("body = %s, want generic auth failure", body)
			}
			if strings.Contains(body, "required") || strings.Contains(body, "invalid") {
				t.Fatalf("body disclosed auth failure category: %s", body)
			}
		})
	}
}

func TestAdminHealthRequiresAdminToken(t *testing.T) {
	handler := NewHandler(&recordingKMS{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte(adminTestToken))
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	req.Header.Set(adminTokenHeader, adminTestToken)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"service":"aegis-admin"`) {
		t.Fatalf("body = %s, want admin health payload", rec.Body.String())
	}
}

func TestConstantTimeEqualHandlesLengthMismatch(t *testing.T) {
	if !constantTimeEqual([]byte(adminTestToken), []byte(adminTestToken)) {
		t.Fatal("constantTimeEqual rejected equal tokens")
	}
	for _, token := range [][]byte{
		[]byte("wrong-token"),
		[]byte("bad"),
		nil,
	} {
		if constantTimeEqual(token, []byte(adminTestToken)) {
			t.Fatalf("constantTimeEqual accepted %q", token)
		}
	}
}

type recordingKMS struct {
	storeCalls int
}

func (r *recordingKMS) GetKey(ctx context.Context, keyID string) (*utils.SecureBytes, error) {
	return nil, nil
}

func (r *recordingKMS) StoreKey(ctx context.Context, keyID string, plaintext []byte) error {
	r.storeCalls++
	return nil
}

func (r *recordingKMS) DeleteKey(ctx context.Context, keyID string) error {
	return nil
}

func (r *recordingKMS) RotateKey(ctx context.Context, keyID string) error {
	return nil
}

func (r *recordingKMS) ListKeyIDs(ctx context.Context) ([]string, error) {
	return nil, nil
}

func (r *recordingKMS) Close() error {
	return nil
}

func TestIssueVirtualKeyReturnsJWT(t *testing.T) {
	signingKey := []byte("0123456789abcdef0123456789abcdef")
	handler := NewHandlerWithServices(&recordingKMS{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte(adminTestToken), Services{
		SigningKey:    signingKey,
		Issuer:        "aegis",
		MaxTTL:        24 * time.Hour,
		AllowedModels: []string{"gpt-4o-mini"},
		Now:           func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/admin/keys/virtual", strings.NewReader(`{"subject":"client-1","models":["gpt-4o-mini"],"ttl":"1h","tpm":4000,"budget":5}`))
	req.Header.Set(adminTokenHeader, adminTestToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var payload issueVirtualKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	claims, err := virtualkey.ValidateAt(payload.VirtualKey, signingKey, "aegis", 24*time.Hour, time.Unix(1_800_000_000, 0).UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ValidateAt: %v", err)
	}
	if claims.MaxTPM != 4000 || claims.BudgetUSD != 5 {
		t.Fatalf("claims tpm=%d budget=%f", claims.MaxTPM, claims.BudgetUSD)
	}
}

func TestIssueVirtualKeyRejectsUnconfiguredModel(t *testing.T) {
	handler := NewHandlerWithServices(&recordingKMS{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte(adminTestToken), Services{
		SigningKey:    []byte("0123456789abcdef0123456789abcdef"),
		Issuer:        "aegis",
		MaxTTL:        24 * time.Hour,
		AllowedModels: []string{"gpt-4o-mini"},
	})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/admin/keys/virtual", strings.NewReader(`{"subject":"client-1","models":["not-configured"]}`))
	req.Header.Set(adminTokenHeader, adminTestToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRevokeVirtualKeyUsesRevoker(t *testing.T) {
	revoker := &stubRevoker{}
	handler := NewHandlerWithServices(&recordingKMS{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte(adminTestToken), Services{
		Issuer:  "aegis",
		MaxTTL:  24 * time.Hour,
		Revoker: revoker,
	})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodDelete, "/admin/keys/virtual/vk_test", nil)
	req.Header.Set(adminTokenHeader, adminTestToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if revoker.keyID != "vk_test" {
		t.Fatalf("revoked key = %q", revoker.keyID)
	}
}

func TestGetUsageReturnsStoreTotals(t *testing.T) {
	store := quota.NewMemoryStore()
	if err := store.RecordUsage(context.Background(), "vk_test", quota.UsageEntry{CostUSD: 1.25, InputTokens: 10, OutputTokens: 5}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	handler := NewHandlerWithServices(&recordingKMS{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte(adminTestToken), Services{
		Quota: quota.NewManager(store, 0),
	})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/vk_test", nil)
	req.Header.Set(adminTokenHeader, adminTestToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"key_id":"vk_test"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

type stubRevoker struct {
	keyID string
}

func (s *stubRevoker) Revoke(_ context.Context, _, keyID string, _ time.Time, _ time.Duration) (revocation.CommitResult, error) {
	s.keyID = keyID
	return revocation.CommitResult{Changed: true}, nil
}
