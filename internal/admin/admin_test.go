package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/utils"
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
