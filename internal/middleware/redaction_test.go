package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strconv"
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

func TestPIIRedactionReplacesMultipleRulesAndZeroesOwnedInput(t *testing.T) {
	original := []byte(`{"model":"gpt-4o","messages":[{"content":"user@example.com 123-45-6789"}]}`)
	ctx := &server.RequestContext{
		Request:           httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		RequestBody:       original,
		RequestBodyLoaded: true,
	}

	PIIRedaction(RedactionConfig{
		Mode:               ModeRedact,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() {})

	if !bytes.Equal(original, make([]byte, len(original))) {
		t.Fatal("PIIRedaction did not zero the superseded owned input")
	}
	got := string(ctx.RequestBody)
	if !strings.Contains(got, "[EMAIL_REDACTED]") || !strings.Contains(got, "[SSN_REDACTED]") {
		t.Fatalf("redacted body = %q, want email and SSN replacements", got)
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

func TestPIIScannerBoundsFindingsForRepeatedPII(t *testing.T) {
	scanner := newPIIScanner(RedactionConfig{})
	body := []byte(strings.Repeat("123-45-6789 ", 4096))

	findings := scanner.Scan(body)
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want one bounded presence finding", len(findings))
	}
	if findings[0].Rule != "ssn" {
		t.Fatalf("first finding rule = %q, want ssn", findings[0].Rule)
	}
}

func TestPIIRedactionRedactsEscapedSemanticStringValues(t *testing.T) {
	ctx := redactionTestContext(`{"messages":[{"content":"user\u0040example.com"},{"content":"call 555-123\u002d4567"},{"content":"ssn 123-\u0034\u0035-6789"}],"request_id":1e100}`)

	calledNext := false
	PIIRedaction(RedactionConfig{
		Mode:               ModeRedact,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() {
		calledNext = true

		var payload struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
			RequestID json.Number `json:"request_id"`
		}
		decoder := json.NewDecoder(ctx.Request.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			t.Fatalf("Decode redacted body returned error: %v", err)
		}
		got := make([]string, 0, len(payload.Messages))
		for _, message := range payload.Messages {
			got = append(got, message.Content)
		}
		joined := strings.Join(got, " ")
		for _, pii := range []string{"user@example.com", "555-123-4567", "123-45-6789"} {
			if strings.Contains(joined, pii) {
				t.Fatalf("provider-visible semantic content leaked %q: %q", pii, joined)
			}
		}
		for _, placeholder := range []string{"[EMAIL_REDACTED]", "[PHONE_REDACTED]", "[SSN_REDACTED]"} {
			if !strings.Contains(joined, placeholder) {
				t.Fatalf("provider-visible semantic content = %q, want %q", joined, placeholder)
			}
		}
		if payload.RequestID.String() != "1e100" {
			t.Fatalf("request_id = %s, want exact JSON number 1e100", payload.RequestID)
		}
	})

	if !calledNext {
		t.Fatal("PIIRedaction did not call next in redact mode")
	}
	if ctx.IsAborted() {
		t.Fatalf("PIIRedaction aborted redact-mode request with status %d", ctx.StatusCode)
	}
}

func TestPIIRedactionBlocksEscapedSemanticPII(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "email", body: `{"content":"user\u0040example.com"}`},
		{name: "phone", body: `{"content":"555\u002d123-4567"}`},
		{name: "ssn", body: `{"content":"123-\u0034\u0035-6789"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := redactionTestContext(tt.body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeBlock,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction called next for escaped semantic PII")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusBadRequest {
				t.Fatalf("abort = %v, status = %d, want aborted 400", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionDetectsEscapedSemanticPIIAndPreservesOriginalBody(t *testing.T) {
	body := `{"content":"email user\u0040example.com; phone 555-123\u002d4567; ssn 123-\u0034\u0035-6789"}`
	ctx := redactionTestContext(body)

	calledNext := false
	PIIRedaction(RedactionConfig{
		Mode:               ModeDetect,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() {
		calledNext = true
		got, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		if string(got) != body {
			t.Fatalf("detect-mode body = %q, want original %q", got, body)
		}
	})

	if !calledNext {
		t.Fatal("PIIRedaction did not call next in detect mode")
	}
}

func TestPIIRedactionRedactsPIISplitAcrossAdjacentTextContentParts(t *testing.T) {
	tests := []struct {
		name        string
		first       string
		second      string
		secret      string
		replacement string
	}{
		{
			name:        "email",
			first:       "contact user@",
			second:      "example.com now",
			secret:      "user@example.com",
			replacement: "[EMAIL_REDACTED]",
		},
		{
			name:        "phone",
			first:       "call 555-",
			second:      "123-4567 now",
			secret:      "555-123-4567",
			replacement: "[PHONE_REDACTED]",
		},
		{
			name:        "credit_card",
			first:       "card 4111 1111 ",
			second:      "1111 1111 now",
			secret:      "4111 1111 1111 1111",
			replacement: "[CC_REDACTED]",
		},
		{
			name:        "api_key",
			first:       "key sk-abcdefghij",
			second:      "klmnopqrstuv now",
			secret:      "sk-abcdefghijklmnopqrstuv",
			replacement: "[KEY_REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"model": "gpt-4o-mini",
				"messages": []any{map[string]any{
					"role": "user",
					"content": []any{
						map[string]any{"type": "text", "text": tt.first, "metadata": map[string]any{"source": "first"}},
						map[string]any{"text": tt.second, "type": "text", "metadata": map[string]any{"source": "second"}},
					},
				}},
			})
			if err != nil {
				t.Fatalf("Marshal test body returned error: %v", err)
			}
			ctx := redactionTestContext(string(body))
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeRedact,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() {
				calledNext = true
				var payload struct {
					Messages []struct {
						Content []struct {
							Text     string            `json:"text"`
							Metadata map[string]string `json:"metadata"`
						} `json:"content"`
					} `json:"messages"`
				}
				if err := json.NewDecoder(ctx.Request.Body).Decode(&payload); err != nil {
					t.Fatalf("Decode redacted body returned error: %v", err)
				}
				var texts []string
				for _, part := range payload.Messages[0].Content {
					texts = append(texts, part.Text)
				}
				if payload.Messages[0].Content[0].Metadata["source"] != "first" || payload.Messages[0].Content[1].Metadata["source"] != "second" {
					t.Fatalf("redaction dropped content-part metadata: %#v", payload.Messages[0].Content)
				}
				providerVisible := strings.Join(texts, "")
				if strings.Contains(providerVisible, tt.secret) {
					t.Fatalf("provider-visible text leaked split %s: %q", tt.name, providerVisible)
				}
				if !strings.Contains(providerVisible, tt.replacement) {
					t.Fatalf("provider-visible text = %q, want %q", providerVisible, tt.replacement)
				}
			})

			if !calledNext {
				t.Fatalf("PIIRedaction did not call next for redactable split PII; status=%d", ctx.StatusCode)
			}
			if ctx.IsAborted() {
				t.Fatalf("PIIRedaction aborted split-PII redact request with status %d", ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionBlocksAndDetectsPIISplitAcrossInterleavedTextContentParts(t *testing.T) {
	body := []byte(`{"model":"deepseek-chat","messages":[{"role":"user","content":[{"type":"text","text":"user\u0040"},{"type":"image_url","image_url":{"url":"https://example.invalid/safe.png"}},{"type":"text","text":"example.com"}]}]}`)

	blockScanner := newPIIScanner(RedactionConfig{Mode: ModeBlock})
	if _, found, err := blockScanner.ProcessJSON(body, int64(len(body))); !errors.Is(err, errSemanticPIIBlocked) || !found {
		t.Fatalf("block ProcessJSON = found %v, err %v; want found PII and blocked error", found, err)
	}

	detectScanner := newPIIScanner(RedactionConfig{Mode: ModeDetect})
	processed, found, err := detectScanner.ProcessJSON(body, int64(len(body)))
	if err != nil {
		t.Fatalf("detect ProcessJSON returned error: %v", err)
	}
	if !found {
		t.Fatal("detect ProcessJSON did not report split semantic PII")
	}
	if processed != nil {
		t.Fatalf("detect ProcessJSON returned rewritten body %q, want nil", processed)
	}

	redactScanner := newPIIScanner(RedactionConfig{Mode: ModeRedact})
	processed, found, err = redactScanner.ProcessJSON(body, int64(len(body)+256))
	if err != nil {
		t.Fatalf("redact ProcessJSON returned error: %v", err)
	}
	if !found || strings.Contains(string(processed), "user@") || strings.Contains(string(processed), "example.com") {
		t.Fatalf("redact ProcessJSON did not remove interleaved split PII: found=%v body=%s", found, processed)
	}
	for _, want := range []string{"[EMAIL_REDACTED]", "https://example.invalid/safe.png"} {
		if !strings.Contains(string(processed), want) {
			t.Fatalf("redact ProcessJSON body = %s, want preserved %q", processed, want)
		}
	}
}

func TestPIIRedactionDoesNotConcatenateUnrelatedJSONStrings(t *testing.T) {
	tests := map[string]string{
		"non-text content parts": `{"model":"gpt-4o-mini","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"user@"}},{"type":"image_url","image_url":{"url":"example.com"}}]}]}`,
		"different messages":     `{"model":"gpt-4o-mini","messages":[{"role":"user","content":[{"type":"text","text":"user@"}]},{"role":"user","content":[{"type":"text","text":"example.com"}]}]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeBlock,
				MaxRequestBodySize: int64(len(body) + 1),
			})(ctx, func() { calledNext = true })

			if !calledNext || ctx.IsAborted() {
				t.Fatalf("unrelated strings were treated as one semantic text run: calledNext=%v aborted=%v", calledNext, ctx.IsAborted())
			}
		})
	}
}

func TestPIIRedactionRejectsCaseAliasesInTextContentPartSchema(t *testing.T) {
	tests := map[string]string{
		"type alias":    `{"model":"gpt-4o-mini","messages":[{"content":[{"Type":"text","text":"user@"},{"type":"text","text":"example.com"}]}]}`,
		"text alias":    `{"model":"gpt-4o-mini","messages":[{"content":[{"type":"text","Text":"user@"},{"type":"text","text":"example.com"}]}]}`,
		"escaped alias": `{"model":"gpt-4o-mini","messages":[{"content":[{"\u0054ype":"text","text":"safe"}]}]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeRedact,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction forwarded an ambiguous content-part field alias")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusBadRequest {
				t.Fatalf("abort = %v, status = %d, want invalid-body 400", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionRedactsUnionOfOverlappingDefaultRuleMatches(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		replacement string
	}{
		{name: "china_id_contains_phone_shape", secret: "11010519491231002X", replacement: "[ID_REDACTED]"},
		{name: "credit_card_contains_phone_shape", secret: "4111111111111111", replacement: "[CC_REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"messages":[{"content":"secret ` + tt.secret + ` end"}]}`
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeRedact,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() {
				calledNext = true
				redacted, err := io.ReadAll(ctx.Request.Body)
				if err != nil {
					t.Fatalf("ReadAll returned error: %v", err)
				}
				if strings.Contains(string(redacted), tt.secret) {
					t.Fatalf("redacted body retained overlapping secret: %s", redacted)
				}
				if !strings.Contains(string(redacted), tt.replacement) {
					t.Fatalf("redacted body = %s, want widest-match replacement %q", redacted, tt.replacement)
				}
			})

			if !calledNext || ctx.IsAborted() {
				t.Fatalf("overlap redaction did not forward safely: calledNext=%v aborted=%v", calledNext, ctx.IsAborted())
			}
		})
	}
}

func TestPIIRedactionRejectsMalformedOrTrailingJSON(t *testing.T) {
	for _, body := range []string{
		`{"content":"unterminated}`,
		`{"content":"safe"} {"content":"second"}`,
	} {
		t.Run(body, func(t *testing.T) {
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeDetect,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction called next for invalid JSON")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusBadRequest {
				t.Fatalf("abort = %v, status = %d, want aborted 400", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionRejectsDuplicateObjectMembersAtAnyDepth(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "top-level model",
			body: `{"model":"first","model":"second","messages":[]}`,
		},
		{
			name: "nested escaped equivalent key",
			body: `{"messages":[{"content":"safe","\u0063ontent":"also safe"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := redactionTestContext(tt.body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeDetect,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction called next for duplicate JSON object member")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusBadRequest {
				t.Fatalf("abort = %v, status = %d, want aborted 400", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionRejectsPIIInObjectKeysInsteadOfRenamingSchema(t *testing.T) {
	ctx := redactionTestContext(`{"user\u0040example.com":"safe","content":"safe"}`)
	calledNext := false

	PIIRedaction(RedactionConfig{
		Mode:               ModeRedact,
		MaxRequestBodySize: redactionTestBodyLimit,
	})(ctx, func() { calledNext = true })

	if calledNext {
		t.Fatal("PIIRedaction forwarded PII embedded in an object member name")
	}
	if !ctx.IsAborted() || ctx.StatusCode != http.StatusBadRequest {
		t.Fatalf("abort = %v, status = %d, want blocked 400", ctx.IsAborted(), ctx.StatusCode)
	}
}

func TestPIIRedactionRejectsPIIInNumericValuesInsteadOfChangingJSONType(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-4o-mini","phone":5551234567}`,
		`{"model":"gpt-4o-mini","phone":5.551234567e9}`,
		`{"model":"gpt-4o-mini","phone":5551234567.000}`,
		`{"model":"gpt-4o-mini","card":4111111111111111}`,
		`{"model":"gpt-4o-mini","card":4.111111111111111e15}`,
	} {
		t.Run(body, func(t *testing.T) {
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeRedact,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction forwarded PII encoded as a JSON number")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusBadRequest {
				t.Fatalf("abort = %v, status = %d, want blocked 400", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionRejectsCaseAliasesForSecurityDecisionFields(t *testing.T) {
	for _, body := range []string{
		`{"Model":"gpt-4o-mini","messages":[]}`,
		`{"model":"forbidden","MODEL":"gpt-4o-mini","messages":[]}`,
		`{"model":"gpt-4o-mini","\u0053tream":true,"messages":[]}`,
	} {
		t.Run(body, func(t *testing.T) {
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeRedact,
				MaxRequestBodySize: redactionTestBodyLimit,
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction forwarded a case alias for model/stream")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusBadRequest {
				t.Fatalf("abort = %v, status = %d, want invalid-body 400", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionFailsClosedWhenRedactedBodyExceedsLimit(t *testing.T) {
	body := `{"content":"x"}`
	ctx := redactionTestContext(body)
	replacement := strings.Repeat("R", 64)

	calledNext := false
	PIIRedaction(RedactionConfig{
		Mode: ModeRedact,
		Rules: []RedactionRule{{
			Name:        "expanding",
			Pattern:     regexp.MustCompile(`x`),
			Replacement: replacement,
			Enabled:     true,
		}},
		MaxRequestBodySize: int64(len(body)),
	})(ctx, func() { calledNext = true })

	if calledNext {
		t.Fatal("PIIRedaction called next with an oversized redacted body")
	}
	if !ctx.IsAborted() || ctx.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("abort = %v, status = %d, want aborted 413", ctx.IsAborted(), ctx.StatusCode)
	}
}

func TestPIIRedactionFailsClosedOnSemanticJSONComplexity(t *testing.T) {
	deep := strings.Repeat("[", maxSemanticJSONDepth+2) + `"safe"` + strings.Repeat("]", maxSemanticJSONDepth+2)

	var members strings.Builder
	members.WriteByte('{')
	for i := 0; i <= maxSemanticJSONObjectMembers; i++ {
		if i > 0 {
			members.WriteByte(',')
		}
		members.WriteString(`"k`)
		members.WriteString(strconv.Itoa(i))
		members.WriteString(`":0`)
	}
	members.WriteByte('}')

	values := "[" + strings.Repeat("0,", maxSemanticJSONValues) + "0]"
	for name, body := range map[string]string{
		"depth":          deep,
		"object_members": members.String(),
		"total_values":   values,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeRedact,
				MaxRequestBodySize: int64(len(body) + 1),
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction forwarded over-complex semantic JSON")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("abort = %v, status = %d, want bounded 413", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestPIIRedactionEnforcesSemanticMemoryEnvelope(t *testing.T) {
	var contentPartMembers strings.Builder
	contentPartMembers.WriteString(`{"messages":[{"content":[{"type":"image_url"`)
	for i := 0; i < maxSemanticJSONObjectMembers; i++ {
		contentPartMembers.WriteString(`,"k`)
		contentPartMembers.WriteString(strconv.Itoa(i))
		contentPartMembers.WriteString(`":0`)
	}
	contentPartMembers.WriteString(`}]}]}`)

	tests := map[string]string{
		"body":                 `{"padding":"` + strings.Repeat("x", maxSemanticRequestBodyBytes) + `"}`,
		"single string":        `{"content":"` + strings.Repeat("x", maxSemanticJSONStringBytes+1) + `"}`,
		"content part members": contentPartMembers.String(),
		"content parts aggregate": `{"messages":[{"content":[` +
			`{"type":"text","text":"` + strings.Repeat("a", maxSemanticJoinedTextBytes/4) + `"},` +
			`{"type":"text","text":"` + strings.Repeat("b", maxSemanticJoinedTextBytes/4) + `"},` +
			`{"type":"text","text":"` + strings.Repeat("c", maxSemanticJoinedTextBytes/4) + `"},` +
			`{"type":"text","text":"` + strings.Repeat("d", maxSemanticJoinedTextBytes/4) + `"},` +
			`{"type":"text","text":"safe"}]}` + `]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := redactionTestContext(body)
			calledNext := false
			PIIRedaction(RedactionConfig{
				Mode:               ModeRedact,
				MaxRequestBodySize: int64(maxSemanticRequestBodyBytes * 2),
			})(ctx, func() { calledNext = true })

			if calledNext {
				t.Fatal("PIIRedaction forwarded a request outside the semantic memory envelope")
			}
			if !ctx.IsAborted() || ctx.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("abort = %v, status = %d, want bounded 413", ctx.IsAborted(), ctx.StatusCode)
			}
		})
	}
}

func TestSemanticContentPartInspectorHasBoundedAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation regression")
	}
	var raw strings.Builder
	raw.WriteString(`{"type":"image_url"`)
	for i := 0; i < maxSemanticJSONObjectMembers-1; i++ {
		raw.WriteString(`,"k`)
		raw.WriteString(strconv.Itoa(i))
		raw.WriteString(`":0`)
	}
	raw.WriteByte('}')
	part := []byte(raw.String())

	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			isText, text, err := inspectSemanticTextContentPart(part)
			if err != nil {
				b.Fatalf("inspectSemanticTextContentPart returned error: %v", err)
			}
			if isText || text != "" {
				b.Fatalf("inspector classified non-text part as text: isText=%v text=%q", isText, text)
			}
		}
	})
	maxAllocated := int64(len(part)) * 40
	t.Logf("inspector allocation: %d bytes/op for %d-byte part", result.AllocedBytesPerOp(), len(part))
	if got := result.AllocedBytesPerOp(); got > maxAllocated {
		t.Fatalf("inspector allocated bytes/op = %d, want <= %d for %d-byte adversarial part", got, maxAllocated, len(part))
	}
}

func TestPIIRedactionLargeSafeStringHasBoundedAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation regression")
	}
	value := strings.Repeat("x", maxSemanticJSONStringBytes/2)
	body := []byte(`{"messages":[{"content":"` + value + `"}]}`)
	scanner := newPIIScanner(RedactionConfig{Mode: ModeRedact})

	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			processed, _, err := scanner.ProcessJSON(body, int64(len(body)+16))
			if err != nil {
				b.Fatalf("ProcessJSON returned error: %v", err)
			}
			runtime.KeepAlive(processed)
		}
	})
	// Input is caller-owned. The parser, decoded string, bounded canonical output,
	// and JSON quoting must remain well below the former multi-copy 64 MiB path.
	maxAllocated := int64(len(body))*16 + 256*1024
	if got := result.AllocedBytesPerOp(); got > maxAllocated {
		t.Fatalf("allocated bytes/op = %d, want <= %d for %d-byte body", got, maxAllocated, len(body))
	}
}

func redactionTestContext(body string) *server.RequestContext {
	return &server.RequestContext{
		Request: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)),
	}
}
