# Aegis Runtime Architecture Design

## Status

Accepted baseline for the current framework build-out.

## Architecture Drivers

| Attribute | Stimulus | Response | Measure | Rank | Source / Assumption |
| --- | --- | --- | --- | --- | --- |
| Security | A client sends an unauthenticated or forged virtual key request | Reject before body processing, routing, KMS, or proxy work | No provider egress and no KMS lookup before auth success | 1 | `SECURITY.md`, ADR-001 |
| Secret handling | A provider key is needed for one upstream request | Fetch from KMS only after routing, hold in request scope, close after proxy returns | No plaintext provider key in config, logs, or long-lived caches | 2 | ADR-002, ADR-003 |
| Egress control | A configured provider URL or transformed target is malicious | Validate normalized URL host against an allowlist before outbound request | Exact host or subdomain match only; empty allowlist fails closed | 3 | `AGENTS.md`, `SECURITY.md` |
| Pipeline integrity | A new middleware is added | Preserve ADR-004 order unless a new ADR changes it | Composition tests cover middleware order | 4 | ADR-004 |
| Maintainability | Provider, KMS, or limiter implementation changes | Change the implementation behind a stable interface without changing server microkernel | `internal/server` does not import concrete middleware packages | 5 | Module design assumption |
| MVP operability | Standalone users run a local gateway | Local KMS, in-memory limiter, and strict config validation start without external services | `go test ./...` and example config load pass in a Go toolchain | 6 | README deployment modes |

## Architectural Style

Aegis remains a single-process modular gateway: a microkernel HTTP server plus a middleware pipeline. This avoids distributed-system cost while keeping provider, KMS, limiter, adapter, and proxy modules independently replaceable.

The composition root is `internal/runtime`. It owns concrete wiring from configuration to interfaces. `internal/server` owns only request dispatch, pipeline execution, recovery, request ID, and audit metadata. Middleware packages depend on `internal/server` for the `RequestContext` contract, but `internal/server` does not depend on middleware implementations.

## Runtime Request Flow

```mermaid
flowchart LR
  Client["Client / OpenAI SDK"] --> Server["internal/server"]
  Server --> Recovery["Recovery"]
  Recovery --> RequestID["Request ID"]
  RequestID --> Audit["Audit metadata"]
  Audit --> Auth["Auth / JWT"]
  Auth --> RateLimit["Rate limit"]
  RateLimit --> PII["PII redaction"]
  PII --> Router["Provider router"]
  Router --> KMS["KMS key injection"]
  KMS --> Adapter["Protocol adapter"]
  Adapter --> Proxy["Streaming proxy"]
  Proxy --> Provider["LLM provider"]
```

## Component Boundaries

| Component | Responsibility | Owns | Must Not Own |
| --- | --- | --- | --- |
| `cmd/aegis` | CLI entrypoint and process lifecycle | flags, logger bootstrap, signal handling | pipeline composition details |
| `internal/runtime` | Convert config into a runnable server | middleware order, concrete implementations, default runtime policies | HTTP request execution logic |
| `internal/server` | HTTP microkernel and middleware execution | mux, request context, infrastructure middleware | auth, routing, provider, or KMS policy |
| `internal/config` | Config loading and validation | externalized runtime settings | secrets, live provider clients |
| `internal/middleware` | Request policy controls | auth, rate limiting, PII, routing, adapter, KMS, proxy middleware contracts | network transport implementation |
| `internal/kms` | Provider key storage abstraction | encrypted key lifecycle | request authorization decisions |
| `internal/proxy` | Upstream HTTP/SSE forwarding | outbound transport, egress validation, response forwarding | model authorization or key resolution |
| `internal/quota` | Budget accounting | usage and cost data | auth or request routing |

## Deployment Topology

MVP topology is one Aegis process behind a trusted ingress or localhost development binding. Production topology should place `/v1/*` behind TLS or mTLS and keep any future admin API on a separate listener or internal-only network. The current local KMS runtime uses an in-memory backend for framework validation; a persistent encrypted local store or Vault mode is required before production use.

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
| Example config load test | `aegis.example.json` parses and validates with required env vars | Every config change |
| Egress validation tests | Empty allowlist fails closed; host matching is exact/suffix-safe | Every proxy change |
| Secret handling tests | KMS StoreKey zeroes plaintext and SecureBytes closes after use | Every KMS change |
| Auth tests | Invalid, expired, wrong issuer, and bad signature JWTs fail closed | Every auth change |
