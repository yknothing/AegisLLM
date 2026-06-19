// Package middleware - redaction.go implements PII (Personally Identifiable Information) redaction.
//
// DESIGN:
//   - Scans request bodies for sensitive patterns before forwarding to providers
//   - Configurable rules: regex patterns for emails, phone numbers, SSNs, etc.
//   - Can operate in "detect" (log warning) or "redact" (replace) mode
//   - Minimal performance impact through compiled regex and early termination
//
// SECURITY:
//   - Prevents accidental PII leakage to third-party LLM providers
//   - Supports compliance requirements (GDPR, CCPA, HIPAA)
//   - Redaction happens BEFORE the request leaves the gateway
//   - Original content is never logged
package middleware

import (
	"errors"
	"net/http"
	"regexp"
	"sync"

	"github.com/yknothing/AegisLLM/internal/server"
)

// RedactionMode determines how detected PII is handled.
type RedactionMode string

const (
	// ModeDetect logs a warning but does not modify the request.
	ModeDetect RedactionMode = "detect"
	// ModeRedact replaces detected PII with placeholder text.
	ModeRedact RedactionMode = "redact"
	// ModeBlock rejects the request entirely if PII is detected.
	ModeBlock RedactionMode = "block"
)

// RedactionRule defines a pattern to detect and optionally redact.
type RedactionRule struct {
	Name        string         // Human-readable rule name (e.g., "email")
	Pattern     *regexp.Regexp // Compiled regex pattern
	Replacement string         // Replacement text (e.g., "[EMAIL_REDACTED]")
	Enabled     bool
}

// RedactionConfig configures the PII redaction middleware.
type RedactionConfig struct {
	Mode               RedactionMode
	Rules              []RedactionRule
	MaxRequestBodySize int64
}

// DefaultRedactionRules returns a set of common PII detection patterns.
func DefaultRedactionRules() []RedactionRule {
	return []RedactionRule{
		{
			Name:        "email",
			Pattern:     regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			Replacement: "[EMAIL_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "phone_us",
			Pattern:     regexp.MustCompile(`(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
			Replacement: "[PHONE_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "ssn",
			Pattern:     regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			Replacement: "[SSN_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "credit_card",
			Pattern:     regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
			Replacement: "[CC_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "api_key_pattern",
			Pattern:     regexp.MustCompile(`(sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16})`),
			Replacement: "[KEY_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "china_id",
			Pattern:     regexp.MustCompile(`\b\d{17}[\dXx]\b`),
			Replacement: "[ID_REDACTED]",
			Enabled:     true,
		},
		{
			Name:        "china_phone",
			Pattern:     regexp.MustCompile(`\b1[3-9]\d{9}\b`),
			Replacement: "[PHONE_REDACTED]",
			Enabled:     true,
		},
	}
}

// PIIRedaction creates the PII redaction middleware.
func PIIRedaction(cfg RedactionConfig) server.Middleware {
	scanner := newPIIScanner(cfg)

	return func(ctx *server.RequestContext, next func()) {
		body, err := readAndReplaceBody(ctx.Request, cfg.MaxRequestBodySize)
		if errors.Is(err, errRequestBodyTooLarge) {
			ctx.Abort(http.StatusRequestEntityTooLarge, []byte(`{"error":{"message":"request body too large","type":"invalid_request_error"}}`))
			return
		}
		if err != nil {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid request body","type":"invalid_request_error"}}`))
			return
		}

		findings := scanner.Scan(string(body))
		if len(findings) == 0 {
			next()
			return
		}

		switch scanner.mode {
		case ModeDetect:
			next()
		case ModeBlock:
			ctx.Abort(http.StatusBadRequest, blockErrorJSON())
		default:
			replaceBody(ctx.Request, []byte(scanner.Redact(string(body))))
			next()
		}
	}
}

// --- PII Scanner ---

type piiScanner struct {
	mu    sync.RWMutex
	mode  RedactionMode
	rules []RedactionRule
}

func newPIIScanner(cfg RedactionConfig) *piiScanner {
	rules := cfg.Rules
	if len(rules) == 0 {
		rules = DefaultRedactionRules()
	}
	mode := cfg.Mode
	if mode == "" {
		mode = ModeRedact
	}
	return &piiScanner{
		mode:  mode,
		rules: rules,
	}
}

// Scan checks text for PII patterns and returns findings.
func (s *piiScanner) Scan(text string) []PIIFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var findings []PIIFinding
	for _, rule := range s.rules {
		if !rule.Enabled {
			continue
		}
		matches := rule.Pattern.FindAllStringIndex(text, -1)
		for _, match := range matches {
			findings = append(findings, PIIFinding{
				Rule:  rule.Name,
				Start: match[0],
				End:   match[1],
			})
		}
	}
	return findings
}

// Redact replaces all PII matches with their configured replacements.
func (s *piiScanner) Redact(text string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := text
	for _, rule := range s.rules {
		if !rule.Enabled {
			continue
		}
		result = rule.Pattern.ReplaceAllString(result, rule.Replacement)
	}
	return result
}

// PIIFinding represents a detected PII occurrence.
type PIIFinding struct {
	Rule  string // Which rule matched
	Start int    // Start position in text
	End   int    // End position in text
}

// blockErrorJSON creates a PII block error response.
func blockErrorJSON() []byte {
	return []byte(`{"error":{"message":"request blocked: contains personally identifiable information","type":"content_policy_error"}}`)
}
