# Aegis Module Boundaries

## Dependency Direction

```mermaid
flowchart TD
  cmd["cmd/aegis"] --> runtime["internal/runtime"]
  cmd --> operator["internal/operator"]
  runtime --> server["internal/server"]
  runtime --> middleware["internal/middleware"]
  runtime --> kms["internal/kms"]
  runtime --> egress["internal/egress"]
  runtime --> proxy["internal/proxy"]
  runtime --> config["internal/config"]
  runtime --> revocation["internal/revocation"]
  middleware --> virtualkey["internal/virtualkey"]
  operator --> virtualkey
  operator --> revocation
  operator --> kms
  middleware --> server
  middleware --> kms
  middleware --> proxy
  proxy --> egress
  proxy --> utils["internal/utils"]
  kms --> utils
```

The server microkernel must stay stable. Concrete policy modules depend on it, and runtime composes them. The server package must not import `internal/middleware`, otherwise the pipeline becomes tightly coupled and harder to test.

## Module Contracts

### `internal/runtime`

Responsibility: assemble a configured Aegis server from stable module interfaces.

Exports:
- `NewServer(cfg *config.Config, logger *slog.Logger) (*server.Server, error)`
  - Purpose: build middleware in ADR-004 order and return a runnable server.
  - Errors: missing signing key, invalid KMS config, invalid provider config.
  - Invariant: all provider egress hosts are allowlisted before proxy middleware is created.
  - Invariant: egress host matching uses `internal/egress`; exact entries match only exact hosts and subdomains require explicit `*.` wildcard entries.

### `internal/server`

Responsibility: execute HTTP requests through an ordered middleware pipeline.

Exports:
- `New(cfg *config.Config, logger *slog.Logger, opts ...Option) (*Server, error)`
- `WithMiddleware(m Middleware) Option`
- `RequestContext`

Internal:
- HTTP mux registration.
- Recovery, request ID, and audit metadata middleware.
- The main gateway currently mounts only `POST /v1/chat/completions` and the Go `GET /health` pattern, which also serves HTTP `HEAD`.
- A middleware chain that reaches its terminal boundary without producing a response fails closed with `500`.
- A terminal middleware commits or aborts without delegating; middleware that calls `next()` remains non-terminal and may not defer the only response write until unwind.

### `internal/middleware`

Responsibility: enforce request policy and transform request context before proxying.

Exports:
- `Auth`, `RateLimiter`, `PIIRedaction`, `Router`, `KMSInjector`, `Adapter`, `Proxy`

Invariants:
- Auth runs before any body scanning or KMS access.
- Router validates model permission before KMS key resolution.
- KMS key resolution is pool-only in `v0.2.1` and fails closed for reserved BYOK key sources until owner/provider binding exists.
- PII, router, and adapter share one bounded request-scoped body buffer; no middleware may independently re-read and retain a second body copy.
- Adapter may replace the owned request body and target path, but must not log body content; replaced and final buffers are zeroed.
- Router circuit-breaker state may consume only outcome fields set by the proxy boundary.

### `internal/proxy`

Responsibility: safely forward requests to an upstream provider.

Exports:
- `NewEngine(cfg StreamConfig) *Engine`
- `ProxyRequest(...) (*ProxyResult, error)`

Invariants:
- Egress host must pass allowlist validation.
- Exact egress entries match only exact hosts; wildcard entries such as `*.example.com` allow nested subdomains but not the apex host.
- The bounded request body is forwarded from the pipeline-owned buffer; provider responses are streamed and neither body is logged.
- Hop-by-hop and client credential headers are stripped before upstream forwarding.

### `internal/operator`

Responsibility: coordinate privileged offline provisioning without introducing
a network trust boundary. Provider-key import resolves an enabled provider to
its configured KMS key ID; virtual-key issuance uses `internal/virtualkey`;
revocation and KMS migration use durable local contracts.

### `internal/revocation`

Responsibility: own the versioned single-host revocation snapshot, serialized
atomic writer, bounded polling reader, and fail-closed checker contract. Shared
or multi-host backends must replace this module behind the checker seam rather
than sharing its local file over a network filesystem.

### `internal/virtualkey`

Responsibility: own the HS256 claims, issuance, and validation contract used by
both the offline operator path and runtime Auth middleware.

## Change Scenarios

| Scenario | Expected modules touched | Boundary verdict |
| --- | --- | --- |
| Add a Redis limiter | `internal/middleware/ratelimit.go`, runtime config mapping | Isolated |
| Add RS256 virtual keys | `internal/middleware/auth.go`, config, tests | Isolated if auth interface stays stable |
| Add Anthropic request conversion | `internal/middleware/adapter.go`, adapter tests | Isolated |
| Move local KMS file blobs to another durable backend | `internal/kms/local`, runtime backend wiring | Isolated |
| Change middleware order | ADR, `internal/runtime`, order tests | Requires architecture review |
| Add quota enforcement | `internal/quota`, new middleware, runtime config mapping, durable store | Requires architecture review because it changes request rejection semantics |
| Mount Admin API | `internal/admin`, `cmd/aegis` or runtime listener wiring, auth/audit config | Requires architecture review because it adds a new trust boundary |
