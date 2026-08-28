package middleware

import (
	"bytes"
	"net/http"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
)

// captureWriter buffers an upstream attempt so Router can discard retryable
// failures without committing the client response (ADR-006).
type captureWriter struct {
	header     http.Header
	body       bytes.Buffer
	status     int
	wroteHead  bool
	overflowed bool
}

func newCaptureWriter() *captureWriter {
	return &captureWriter{header: make(http.Header), status: http.StatusOK}
}

func (w *captureWriter) Header() http.Header { return w.header }

func (w *captureWriter) WriteHeader(statusCode int) {
	if w.wroteHead {
		return
	}
	w.wroteHead = true
	w.status = statusCode
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if !w.wroteHead {
		w.WriteHeader(http.StatusOK)
	}
	if w.body.Len()+len(p) > gatewayconst.MaxCapturedResponseBytes {
		w.overflowed = true
		return len(p), nil
	}
	return w.body.Write(p)
}

func (w *captureWriter) Status() int { return w.status }

func (w *captureWriter) Overflowed() bool { return w.overflowed }

func (w *captureWriter) FlushTo(dst http.ResponseWriter) {
	for key, values := range w.header {
		for _, value := range values {
			dst.Header().Add(key, value)
		}
	}
	dst.WriteHeader(w.status)
	_, _ = dst.Write(w.body.Bytes())
}
