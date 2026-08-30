# Aegis Runtime Architecture Design

## Status

Accepted baseline for the current framework build-out.

## Architecture Drivers

| Attribute | Stimulus | Response | Measure | Rank | Source / Assumption |
| --- | --- | --- | --- | --- | --- |
| Security | A client sends an unauthenticated or forged virtual key request | Reject before body processing, routing, KMS, or proxy work | No provider egress and no KMS lookup before auth success | 1 | `SECURITY.md`, ADR-001 |
| Secret handling | A provider key is needed for one upstream request | Fetch from KMS only after routing, hold in request scope, close after proxy returns | No plaintext provider key in config, logs, or long-lived caches | 2 | ADR-002, ADR-003 |
| Egress control | A configured provider URL, port, or DNS answer is malicious | Validate the HTTPS endpoint, allowlist binding, and every resolved address before each new connection; dial only a validated IP | Host-only/wildcard rules bind port 443; non-default ports and IP literals require exact rules; any non-public DNS answer and an empty/invalid allowlist fail closed | 3 | `AGENTS.md`, `SECURITY.md` |
| Pipeline integrity | A new middleware is added | Preserve ADR-004 order unless a new ADR changes it | Composition tests cover middleware order | 4 | ADR-004 |
| Configuration integrity | An operator mistypes a field or omits an auth boundary | Reject unknown JSON fields and require a non-empty issuer | Typo tests fail during config load at root and nested boundaries | 5 | Fail-closed operating policy |
| Maintainability | Provider, KMS, or limiter implementation changes | Change the implementation behind a stable interface without changing server microkernel | `internal/server` does not import concrete middleware packages | 6 | Module design assumption |
| MVP operability | Standalone users run a local gateway | Local KMS, in-memory limiter, and strict config validation start without external services | `go test ./...` and example config load pass in a Go toolchain | 7 | README deployment modes |

## Architectural Style

Aegis remains a single-process modular gateway: a microkernel HTTP server plus a middleware pipeline. This avoids distributed-system cost while keeping provider, KMS, limiter, adapter, and proxy modules independently replaceable.

The composition root is `internal/runtime`. It owns concrete wiring from configuration to interfaces. `internal/server` owns only exact request dispatch, pipeline execution, recovery, request ID, and audit metadata. Middleware packages depend on `internal/server` for the `RequestContext` contract, but `internal/server` does not depend on middleware implementations.

The data plane is deliberately narrow: `POST /v1/chat/completions` is the provider-facing route, authenticated `GET /v1/models` returns the virtual-key ∩ catalog intersection, and `GET /health` is the liveness route. The pipeline owns the transport body once. PII performs bounded token-level semantic JSON processing and may produce one capped canonical replacement buffer before routing and adaptation reuse it; superseded and final owned byte buffers are zeroed. Provider circuit breakers are updated only from proxy-observed provider responses, never from gateway-local failures. Router may retry KMS → Adapter → Proxy on the same request (ADR-006). Optional quota sits after rate limit and before PII.

## Runtime Request Flow

```mermaid
flowchart LR
  Client["Client / OpenAI SDK"] --> Server["internal/server"]
  Server --> Recovery["Recovery"]
  Recovery --> RequestID["Request ID"]
  RequestID --> Audit["Audit metadata"]
  Audit --> Auth["Auth / JWT"]
  Auth --> RateLimit["Rate limit"]
  RateLimit --> Quota["Quota (optional)"]
  Quota --> PII["PII redaction"]
  PII --> Router["Provider router"]
  Router --> KMS["KMS key injection"]
  KMS --> Adapter["Protocol adapter"]
  Adapter --> Proxy["Streaming proxy"]
  Proxy --> Provider["LLM provider"]
```

## Component Boundaries

| Component | Responsibility | Owns | Must Not Own |
| --- | --- | --- | --- |
| `cmd/aegis` | CLI entrypoint and process lifecycle | server flags, offline operator command parsing, logger/signal bootstrap | pipeline composition or privileged policy details |
| `internal/runtime` | Convert config into a runnable server | middleware order, concrete implementations, default runtime policies | HTTP request execution logic |
| `internal/server` | HTTP microkernel and middleware execution | mux, request context, infrastructure middleware | auth, routing, provider, or KMS policy |
| `internal/config` | Config loading and validation | externalized runtime settings | secrets, live provider clients |
| `internal/middleware` | Request policy controls | auth, rate limiting, PII, routing, adapter, KMS, proxy middleware contracts | network transport implementation |
| `internal/kms` | Provider key storage abstraction | encrypted key lifecycle | request authorization decisions |
| `internal/operator` | Privileged offline workflows | provider import, token issuance/revocation, KMS migration coordination | network listeners or data-plane routes |
| `internal/revocation` | Single-host durable negative auth state | atomic snapshot writer, polling reader, immutable checker | multi-host shared-state claims |
| `internal/virtualkey` | Virtual-key token contract | HS256 issuance and validation | HTTP request handling |
| `internal/proxy` | Upstream HTTP/SSE forwarding | outbound transport, egress validation, response forwarding | model authorization or key resolution |
| `internal/quota` | Budget accounting | usage and cost data | auth or request routing |

## Capability Truth Table

| Capability | Current Runtime Behavior | Guardrail |
| --- | --- | --- |
| Virtual key auth | HS256 issuance/validation, issuer/expiry checks, and durable single-host revocation | RS256 and shared/network control-plane revocation are reserved |
| Rate limiting | Mandatory in-memory RPM and concurrency for v0.2.1 | `enabled=false`, non-positive default RPM/concurrency, Redis backend/URL, and non-zero TPM fail fast until implemented |
| Quota / budget | Package scaffold only, not in request pipeline | `quota.enabled=true`, quota backend/DSN/default-budget fields, and store config are rejected during config validation |
| KMS | Local AES-256-GCM file backend for binary-loaded config; memory backend only for explicit programmatic tests | Missing local path, missing/corrupt/empty enabled-provider credentials, and Vault mode/config fail fast before server startup |
| Admin / BYOK | Handler scaffold exists but main gateway does not mount it | Mutating/query endpoints return `501`; `key_source="byok"` virtual keys fail closed until owner/provider binding exists |
| Provider adapters | OpenAI-compatible `openai` and `deepseek` request path | Anthropic/Gemini are rejected by runtime until adapters are implemented |

## Deployment Topology

MVP topology is one Aegis process behind a trusted ingress or localhost development binding. Its limiter is per authenticated virtual key, not an aggregate process-wide, source-IP, or pre-authentication admission control; the ingress must supply those limits. Production topology should place `POST /v1/chat/completions` behind TLS or mTLS and keep any future admin API on a separate listener or internal-only network. Binary-loaded configuration requires an encrypted local KMS file backend; the in-memory backend remains available only to explicit programmatic tests. Vault remains a separate production hardening track.

Container deployments must provide `AEGIS_MASTER_KEY`, `AEGIS_JWT_KEY`, and a writable local state volume at `/var/lib/aegis` for file-backed KMS and revocation. Initialize revocation state with the same release binary before server start. Production deployments should mount an explicit config at `/etc/aegis/aegis.json`; the bundled config is for smoke validation only.

On shutdown, `server.shutdown_timeout` bounds the graceful phase. If that phase
expires, Aegis force-closes connections and permits at most one additional
equally bounded handler-drain phase before returning an error. If a handler
still does not exit, secret-owning shutdown hooks are deliberately skipped and
the supervisor must terminate the process; Aegis never clears shared runtime
resources while an active handler may still use them.

## Hard Decisions and Exit Cost

| Decision | Benefit | Cost / Exit Story |
| --- | --- | --- |
| Single binary modular gateway | Simple deployment and audit surface | If independent scaling becomes necessary, extract `proxy` and `quota` behind interfaces first |
| Middleware pipeline as policy spine | Security order is explicit and testable | Reordering must go through ADR review and order tests |
| Composition root in `internal/runtime` | Avoids server-to-middleware import cycles | Runtime package can grow; split only when it becomes multi-mode |
| No external JWT dependency for MVP | Supply-chain surface remains minimal | HS256-only baseline; add RS256 through a reviewed crypto boundary later |

## Fitness Functions

| Check | Expected Result | When |
| --- | --- | --- |
| Pipeline order test | ADR-004 order is preserved | Every PR touching runtime or middleware |
| Strict config tests | `aegis.example.json` loads, while unknown root/nested fields and empty auth issuer fail closed | Every config change |
| Egress validation tests | Empty/invalid allowlist, URL metadata, port drift, private/special DNS answers, and DNS rebinding paths fail closed; exact loopback IP+port remains available for hermetic tests | Every proxy change |
| Secret handling tests | KMS StoreKey zeroes plaintext and SecureBytes closes after use | Every KMS change |
| Auth tests | Invalid, expired, wrong issuer, and bad signature JWTs fail closed | Every auth change |
| Body ownership tests | Transport bytes have one owner; semantic processing respects byte/shape/allocation ceilings and zeroes owned superseded/final buffers | Every body-processing change |
| Provider health tests | Provider 429/5xx opens the circuit; gateway-local failures do not | Every router/proxy change |
| Release security tests | Source and final binary `govulncheck` pass under the pinned release toolchain | Every release candidate |
