package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/utils"
)

func TestPipelineExecutesMiddlewaresInOnionOrder(t *testing.T) {
	pipeline := testPipeline()
	var got []string

	for _, name := range []string{"auth", "router", "proxy"} {
		name := name
		pipeline.Use(func(ctx *RequestContext, next func()) {
			got = append(got, "enter:"+name)
			next()
			got = append(got, "exit:"+name)
		})
	}

	pipeline.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	want := []string{
		"enter:auth",
		"enter:router",
		"enter:proxy",
		"exit:proxy",
		"exit:router",
		"exit:auth",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("middleware order = %v, want %v", got, want)
	}
}

func TestPipelineAbortStopsInnerMiddleware(t *testing.T) {
	pipeline := testPipeline()
	innerCalled := false

	pipeline.Use(func(ctx *RequestContext, next func()) {
		ctx.Abort(http.StatusUnauthorized, []byte(`{"error":"unauthorized"}`))
	})
	pipeline.Use(func(ctx *RequestContext, next func()) {
		innerCalled = true
		next()
	})

	recorder := httptest.NewRecorder()
	pipeline.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if innerCalled {
		t.Fatal("inner middleware ran after abort")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if body := recorder.Body.String(); body != `{"error":"unauthorized"}` {
		t.Fatalf("body = %q, want unauthorized JSON", body)
	}
}

func TestPipelineClosesProviderAPIKeyAfterRequest(t *testing.T) {
	pipeline := testPipeline()
	rawSecret := []byte("provider-secret")
	secureSecret := utils.NewSecureBytes(rawSecret)

	pipeline.Use(func(ctx *RequestContext, next func()) {
		ctx.ProviderAPIKey = secureSecret
		next()
	})

	pipeline.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	if secureSecret.Bytes() != nil {
		t.Fatal("provider API key buffer was not released")
	}
	if !bytes.Equal(rawSecret, make([]byte, len(rawSecret))) {
		t.Fatal("provider API key buffer was not zeroed")
	}
}

func TestRecoveryMiddlewareDoesNotLogPanicValueOrRequestSecrets(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	pipeline := &Pipeline{logger: logger}
	pipeline.Use(RecoveryMiddleware(logger))
	pipeline.Use(func(ctx *RequestContext, next func()) {
		panic("secret prompt sk-test-token")
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/chat/completions",
		strings.NewReader(`{"messages":[{"content":"secret prompt"}]}`),
	)
	req.Header.Set("Authorization", "Bearer sk-test-token")

	recorder := httptest.NewRecorder()
	pipeline.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	logOutput := logs.String()
	for _, forbidden := range []string{"secret prompt", "sk-test-token", "Authorization", "messages"} {
		if strings.Contains(logOutput, forbidden) {
			t.Fatalf("panic recovery log leaked %q: %s", forbidden, logOutput)
		}
	}
	if !strings.Contains(logOutput, `"panic_type":"string"`) {
		t.Fatalf("panic recovery log = %s, want panic_type", logOutput)
	}
}

func testPipeline() *Pipeline {
	return &Pipeline{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}
