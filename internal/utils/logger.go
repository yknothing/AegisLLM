// Package utils - logger.go provides a zero-PII audit logger.
//
// SECURITY INVARIANT: This logger MUST NEVER output:
//   - Request bodies (prompts, messages)
//   - Response bodies (completions, generated text)
//   - API keys, tokens, or credentials
//   - User-submitted content of any kind
//
// It ONLY records structural metadata for compliance and debugging.
package utils

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// SensitiveFields defines field names that must NEVER appear in logs.
// This acts as a safety net in case developers accidentally pass sensitive data.
var SensitiveFields = map[string]bool{
	"body":          true,
	"prompt":        true,
	"completion":    true,
	"content":       true,
	"messages":      true,
	"api_key":       true,
	"apikey":        true,
	"token":         true,
	"secret":        true,
	"password":      true,
	"authorization": true,
	"cookie":        true,
}

var safeStructuralFields = map[string]bool{
	"cached_tokens":     true,
	"completion_tokens": true,
	"input_tokens":      true,
	"output_tokens":     true,
	"prompt_tokens":     true,
	"reasoning_tokens":  true,
	"total_tokens":      true,
}

var sensitiveKeyFragments = []string{
	"api_key",
	"apikey",
	"authorization",
	"body",
	"completion",
	"content",
	"cookie",
	"credential",
	"jwt",
	"messages",
	"password",
	"private_key",
	"prompt",
	"secret",
	"token",
}

// SafeHandler wraps a slog.Handler and strips any sensitive fields.
// This is a defense-in-depth measure: even if code accidentally logs
// sensitive data, this handler will redact it.
type SafeHandler struct {
	inner slog.Handler
}

// NewSafeHandler creates a new SafeHandler wrapping the given handler.
func NewSafeHandler(inner slog.Handler) *SafeHandler {
	return &SafeHandler{inner: inner}
}

// Enabled implements slog.Handler.
func (h *SafeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler by filtering sensitive attributes.
func (h *SafeHandler) Handle(ctx context.Context, r slog.Record) error {
	// Create a new record with filtered attributes
	filtered := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		filtered.AddAttrs(sanitizeAttr(a))
		return true
	})
	return h.inner.Handle(ctx, filtered)
}

// WithAttrs implements slog.Handler.
func (h *SafeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Filter sensitive attrs before passing to inner handler
	safe := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		safe = append(safe, sanitizeAttr(a))
	}
	return &SafeHandler{inner: h.inner.WithAttrs(safe)}
}

// WithGroup implements slog.Handler.
func (h *SafeHandler) WithGroup(name string) slog.Handler {
	return &SafeHandler{inner: h.inner.WithGroup(name)}
}

// isSensitiveKey checks if a log field name matches known sensitive patterns.
func isSensitiveKey(key string) bool {
	normalized := normalizeLogKey(key)
	if safeStructuralFields[normalized] {
		return false
	}
	if SensitiveFields[normalized] {
		return true
	}
	for _, fragment := range sensitiveKeyFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func sanitizeAttr(a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}
	resolved := a.Value.Resolve()
	if resolved.Kind() == slog.KindGroup {
		group := resolved.Group()
		safe := make([]slog.Attr, 0, len(group))
		for _, child := range group {
			safe = append(safe, sanitizeAttr(child))
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(safe...)}
	}
	return slog.Attr{Key: a.Key, Value: resolved}
}

func normalizeLogKey(key string) string {
	lower := strings.ToLower(strings.TrimSpace(key))
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_")
	return replacer.Replace(lower)
}

// NewAuditLogger creates a structured logger suitable for audit trails.
// It outputs JSON to the given writer with sensitive field redaction.
func NewAuditLogger(w io.Writer, level slog.Level) *slog.Logger {
	jsonHandler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
	})
	safeHandler := NewSafeHandler(jsonHandler)
	return slog.New(safeHandler)
}
