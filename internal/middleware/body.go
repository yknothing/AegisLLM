package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/utils"
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
	_ = r.Body.Close()
	if err != nil {
		utils.MemZero(body)
		return nil, fmt.Errorf("reading request body: %w", err)
	}

	if int64(len(body)) > limit {
		utils.MemZero(body)
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

func readRequestBody(ctx *server.RequestContext, limit int64) ([]byte, error) {
	if ctx.RequestBodyLoaded {
		return ctx.RequestBody, nil
	}

	body, err := readAndReplaceBody(ctx.Request, limit)
	if err != nil {
		return nil, err
	}
	ctx.RequestBody = body
	ctx.RequestBodyLoaded = true
	return body, nil
}

func replaceRequestBody(ctx *server.RequestContext, body []byte) {
	if !sameBuffer(ctx.RequestBody, body) {
		utils.MemZero(ctx.RequestBody)
	}
	ctx.RequestBody = body
	ctx.RequestBodyLoaded = true
	replaceBody(ctx.Request, body)
}

func sameBuffer(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == 0 && len(b) == 0
	}
	return &a[0] == &b[0]
}
