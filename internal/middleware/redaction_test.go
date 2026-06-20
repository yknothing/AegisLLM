package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/server"
)

const redactionTestBodyLimit int64 = 1024

func TestPIIRedactionRedactsPIIBeforeNext(t *testing.T) {
	ctx := redactionTestContext(`{"model":"gpt-4o","messages":[{"content":"email user@example.com"}]}`)

	calledNext := false
	PIIRedaction(RedactionConfig{
		Mode:               ModeRedact,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() {
		calledNext = true
		body, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		if strings.Contains(string(body), "user@example.com") {
			t.Fatalf("redacted body leaked email: %s", body)
		}
		if !strings.Contains(string(body), "[EMAIL_REDACTED]") {
			t.Fatalf("redacted body = %s, want email replacement", body)
		}
	})

	if !calledNext {
		t.Fatal("PIIRedaction did not call next in redact mode")
	}
	if ctx.IsAborted() {
		t.Fatalf("PIIRedaction aborted redact-mode request with status %d", ctx.StatusCode)
	}
}

func TestPIIRedactionDetectModePreservesBody(t *testing.T) {
	ctx := redactionTestContext(`{"model":"gpt-4o","messages":[{"content":"email user@example.com"}]}`)

	calledNext := false
	PIIRedaction(RedactionConfig{
		Mode:               ModeDetect,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() {
		calledNext = true
		body, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		if !strings.Contains(string(body), "user@example.com") {
			t.Fatalf("detect-mode body = %s, want original email preserved", body)
		}
	})

	if !calledNext {
		t.Fatal("PIIRedaction did not call next in detect mode")
	}
	if ctx.IsAborted() {
		t.Fatalf("PIIRedaction aborted detect-mode request with status %d", ctx.StatusCode)
	}
}

func TestPIIRedactionBlockModeAbortsOnPII(t *testing.T) {
	ctx := redactionTestContext(`{"model":"gpt-4o","messages":[{"content":"ssn 123-45-6789"}]}`)

	calledNext := false
	PIIRedaction(RedactionConfig{
		Mode:               ModeBlock,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("PIIRedaction called next in block mode with detected PII")
	}
	if !ctx.IsAborted() {
		t.Fatal("PIIRedaction did not abort block-mode request with detected PII")
	}
	if ctx.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusBadRequest)
	}
}

func TestPIIRedactionEnforcesBodyLimit(t *testing.T) {
	ctx := redactionTestContext(strings.Repeat("x", int(redactionTestBodyLimit)+1))

	calledNext := false
	PIIRedaction(RedactionConfig{
		Mode:               ModeRedact,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("PIIRedaction called next for an oversized body")
	}
	if !ctx.IsAborted() {
		t.Fatal("PIIRedaction did not abort oversized body")
	}
	if ctx.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func redactionTestContext(body string) *server.RequestContext {
	return &server.RequestContext{
		Request: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)),
	}
}
