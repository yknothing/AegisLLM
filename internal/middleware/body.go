package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/yknothing/AegisLLM/internal/config"
)

const defaultMaxRequestBodySize int64 = config.DefaultMaxRequestBodySize

var errRequestBodyTooLarge = errors.New("request body too large")

func readAndReplaceBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = defaultMaxRequestBodySize
	}
	if limit > config.MaxRequestBodySizeLimit {
		return nil, errRequestBodyTooLarge
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	_ = r.Body.Close()

	if int64(len(body)) > limit {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		r.ContentLength = 0
		return nil, errRequestBodyTooLarge
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return body, nil
}

func replaceBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
}
