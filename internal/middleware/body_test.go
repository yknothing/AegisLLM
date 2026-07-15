package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/server"
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

func TestReadAndReplaceBodyZeroesPartialBufferOnReadError(t *testing.T) {
	body := &capturingReadCloser{
		payload:     []byte("sensitive"),
		terminalErr: errors.New("read failed"),
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Body = body

	if _, err := readAndReplaceBody(req, config.DefaultMaxRequestBodySize); err == nil {
		t.Fatal("readAndReplaceBody accepted a partial read error")
	}
	assertCapturedBuffersZeroed(t, body.captured)
	if !body.closed {
		t.Fatal("request body was not closed after read error")
	}
}

func TestReadAndReplaceBodyZeroesRejectedOversizedBuffer(t *testing.T) {
	body := &capturingReadCloser{payload: []byte("123456789")}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Body = body

	if _, err := readAndReplaceBody(req, 8); !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf("readAndReplaceBody error = %v, want errRequestBodyTooLarge", err)
	}
	assertCapturedBuffersZeroed(t, body.captured)
	if !body.closed {
		t.Fatal("request body was not closed after oversized body")
	}
}

func TestReadRequestBodyCachesOneOwnedBuffer(t *testing.T) {
	ctx := &server.RequestContext{
		Request: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini"}`)),
	}

	first, err := readRequestBody(ctx, config.DefaultMaxRequestBodySize)
	if err != nil {
		t.Fatalf("first readRequestBody returned error: %v", err)
	}
	ctx.Request.Body = errorReadCloser{err: errors.New("body was read more than once")}

	second, err := readRequestBody(ctx, config.DefaultMaxRequestBodySize)
	if err != nil {
		t.Fatalf("second readRequestBody returned error: %v", err)
	}
	if len(first) == 0 || &first[0] != &second[0] {
		t.Fatal("readRequestBody did not return the cached owned buffer")
	}
}

func TestReplaceRequestBodyZeroesSupersededOwnedBuffer(t *testing.T) {
	original := []byte("sensitive prompt")
	ctx := &server.RequestContext{
		Request:           httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		RequestBody:       original,
		RequestBodyLoaded: true,
	}

	replaceRequestBody(ctx, []byte("redacted prompt"))

	for _, b := range original {
		if b != 0 {
			t.Fatal("replaceRequestBody did not zero the superseded buffer")
		}
	}
}

type errorReadCloser struct {
	err error
}

func (r errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r errorReadCloser) Close() error             { return nil }

type capturingReadCloser struct {
	payload     []byte
	offset      int
	terminalErr error
	captured    [][]byte
	closed      bool
}

func (r *capturingReadCloser) Read(p []byte) (int, error) {
	if r.offset < len(r.payload) {
		n := copy(p, r.payload[r.offset:])
		r.offset += n
		r.captured = append(r.captured, p[:n])
		return n, nil
	}
	if r.terminalErr != nil {
		err := r.terminalErr
		r.terminalErr = nil
		return 0, err
	}
	return 0, nil
}

func (r *capturingReadCloser) Close() error {
	r.closed = true
	return nil
}

func assertCapturedBuffersZeroed(t *testing.T, buffers [][]byte) {
	t.Helper()
	if len(buffers) == 0 {
		t.Fatal("reader did not capture any body buffer")
	}
	for _, buffer := range buffers {
		for _, b := range buffer {
			if b != 0 {
				t.Fatalf("discarded request body buffer retained byte %q", b)
			}
		}
	}
}
