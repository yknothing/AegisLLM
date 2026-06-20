package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/config"
)

func TestReadAndReplaceBodyRejectsConfiguredLimitAboveMaximum(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("x"))

	body, err := readAndReplaceBody(req, config.MaxRequestBodySizeLimit+1)
	if !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf("readAndReplaceBody error = %v, want errRequestBodyTooLarge", err)
	}
	if body != nil {
		t.Fatalf("body = %q, want nil", body)
	}
}
