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

func TestRegisterBYOKFailsClosed(t *testing.T) {
	kms := &recordingKMS{}
	handler := NewHandler(kms, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte("admin-token"))

	req := httptest.NewRequest(http.MethodPost, "/admin/keys/byok", strings.NewReader(`{"user_id":"u1","provider":"openai","api_key":"sk-test"}`))
	req.Header.Set("X-Admin-Token", "admin-token")
	rec := httptest.NewRecorder()

	handler.authMiddleware(handler.registerBYOK)(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
	if kms.storeCalls != 0 {
		t.Fatalf("StoreKey calls = %d, want 0", kms.storeCalls)
	}
}

func TestAdminAuthRejectsMissingToken(t *testing.T) {
	handler := NewHandler(&recordingKMS{}, slog.New(slog.NewTextHandler(io.Discard, nil)), []byte("admin-token"))

	req := httptest.NewRequest(http.MethodPost, "/admin/keys/byok", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	handler.authMiddleware(handler.registerBYOK)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
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
