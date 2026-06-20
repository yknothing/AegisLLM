package server

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/requestid"
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

func TestRequestIDMiddlewarePreservesSafeClientRequestID(t *testing.T) {
	pipeline := testPipeline()
	pipeline.Use(RequestIDMiddleware())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(requestid.Header, "client_req-123.OK:trace")
	recorder := httptest.NewRecorder()

	pipeline.ServeHTTP(recorder, req)

	if got := recorder.Header().Get(requestid.Header); got != "client_req-123.OK:trace" {
		t.Fatalf("request id = %q, want safe client value", got)
	}
}

func TestRequestIDMiddlewareUsesParsedHTTPHeaderValue(t *testing.T) {
	pipeline := testPipeline()
	pipeline.Use(RequestIDMiddleware())
	rawRequest := strings.Join([]string{
		"POST /v1/chat/completions HTTP/1.1",
		"Host: example.test",
		"X-Request-ID:   parsed-safe-id",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil {
		t.Fatalf("ReadRequest returned error: %v", err)
	}
	recorder := httptest.NewRecorder()

	pipeline.ServeHTTP(recorder, req)

	if got := recorder.Header().Get(requestid.Header); got != "parsed-safe-id" {
		t.Fatalf("request id = %q, want parsed header value", got)
	}
}

func TestRequestIDMiddlewareRegeneratesUnsafeClientRequestID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{name: "empty", id: ""},
		{name: "raw header map leading space", id: " client-req"},
		{name: "trailing space", id: "client-req "},
		{name: "line feed", id: "client\nreq"},
		{name: "carriage return", id: "client\rreq"},
		{name: "tab", id: "client\treq"},
		{name: "separator", id: "client/req"},
		{name: "non ascii", id: "client-请求"},
		{name: "too long", id: strings.Repeat("a", requestid.MaxLength+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := testPipeline()
			pipeline.Use(RequestIDMiddleware())

			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Header.Set(requestid.Header, tt.id)
			recorder := httptest.NewRecorder()

			pipeline.ServeHTTP(recorder, req)

			got := recorder.Header().Get(requestid.Header)
			if got == tt.id {
				t.Fatalf("request id preserved unsafe value %q", got)
			}
			if !strings.HasPrefix(got, "req_") || !requestid.Safe(got) {
				t.Fatalf("regenerated request id = %q, want safe generated id", got)
			}
		})
	}
}

func TestAuditMiddlewareLogsVirtualKeyIDNotVirtualKeyToken(t *testing.T) {
	var logs bytes.Buffer
	logger := utils.NewAuditLogger(&logs, slog.LevelInfo)
	pipeline := &Pipeline{logger: logger}
	pipeline.Use(AuditMiddleware(logger))
	pipeline.Use(func(ctx *RequestContext, next func()) {
		ctx.VirtualKeyID = "vk_test_id"
		ctx.ProviderID = "openai-main"
		ctx.Model = "gpt-4o"
		ctx.StatusCode = http.StatusOK
		next()
	})

	pipeline.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))

	logOutput := logs.String()
	if !strings.Contains(logOutput, `"virtual_key_id":"vk_test_id"`) {
		t.Fatalf("audit log = %s, want virtual_key_id metadata", logOutput)
	}
	if strings.Contains(logOutput, `"virtual_key":`) {
		t.Fatalf("audit log used ambiguous virtual_key field: %s", logOutput)
	}
}

func testPipeline() *Pipeline {
	return &Pipeline{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}
