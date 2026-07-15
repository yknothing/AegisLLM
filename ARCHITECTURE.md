# AegisLLM Architecture Truth Surface

## Version

| Field | Value |
| --- | --- |
| Architecture version | `v0.2.1` |
| Supersedes | `v0.2.0` hardened standalone baseline |
| Status | Current runtime truth |
| Scope | Capability status, runtime dependencies, and reserved architecture targets |

## Current Runtime Shape

AegisLLM is a single-process, security-first LLM API gateway built as a microkernel HTTP server plus an ordered middleware pipeline.

```text
Client
  -> internal/server
  -> Auth
  -> RateLimit
  -> PII Redaction
  -> Router
  -> KMS Injector
  -> Adapter
  -> Proxy
  -> Provider
```

The main gateway mounts only `POST /v1/chat/completions` and the Go `GET /health` pattern (which also serves HTTP `HEAD`). Unsupported data-plane methods and paths never enter the policy pipeline. Admin routes exist as a scaffold in `internal/admin` but are not mounted by `cmd/aegis`.

## Implemented Baseline

| Capability | Runtime status |
| --- | --- |
| Auth | HS256 virtual-key validation, issuer/expiry checks, durable single-host revocation with fail-closed degraded state |
| Rate limiting | In-memory RPM and concurrency |
| PII | Default regex redaction mode |
| Routing | Enabled provider selection by model, priority, and circuit-breaker state |
| Provider health | Circuit breakers consume only proxy-observed provider 429/5xx outcomes; gateway-local failures do not poison provider health |
| KMS | Local AES-256-GCM v2 envelope with keyID AAD, explicit compatibility migration, and strict-v2 post-migration floor |
| Operator | Offline provider-key import, virtual-key issue/revoke, revocation initialization, and KMS migration |
| Providers | OpenAI-compatible `openai` and `deepseek` request path |
| Request body | One bounded request-scoped buffer shared by PII, router, adapter, and proxy, then zeroed at pipeline completion |
| Proxy | Streaming response forwarding, egress allowlist validation, heuristic token counting |
| Config | Unknown JSON fields, empty auth issuer, and unsupported/reserved capabilities fail closed during load |
| TLS | Server TLS with TLS 1.3 baseline; mTLS requires `ca_file` |

## Reserved Capabilities

These are architecture targets, not current runtime capabilities:

| Capability | Current guardrail |
| --- | --- |
| Redis rate limiter | `rate_limit.backend="redis"` or configured `rate_limit.redis_url` fails fast |
| TPM enforcement | Non-zero configured TPM or JWT TPM fails closed |
| Quota / budget enforcement | `quota.enabled=true` fails fast |
| Quota storage/default budget config | Configured `quota.backend`, `quota.dsn`, or `quota.default_budget` fails fast |
| Control-plane store config | Configured `store` persistence fields fail fast |
| Vault KMS | `kms.mode="vault"` or configured `kms.vault` fails fast |
| Admin API / BYOK control plane | Handler scaffold exists; not mounted by main gateway |
| BYOK key source | `key_source="byok"` virtual keys fail closed until owner/provider binding exists |
| RS256 virtual keys | Reserved pending reviewed key loading and rotation |
| Anthropic/Gemini adapters | Runtime rejects unsupported provider types |

## Runtime Dependencies

The default standalone profile needs:

- `AEGIS_MASTER_KEY`
- `AEGIS_JWT_KEY`
- an explicit config file
- `egress.allowed_domains`
- at least one enabled provider whose `api_key_id` references a KMS key
- a writable key-store path when using local file KMS
- an initialized owner-only revocation snapshot on durable local storage

Container smoke runs can use the bundled `/etc/aegis/aegis.json`. Production container deployments should mount `/etc/aegis/aegis.json` explicitly and must provide a writable `/var/lib/aegis` volume when using file-backed local KMS.

`egress.allowed_domains` entries are exact hosts by default. Use an explicit `*.` entry, such as `*.example.com`, when subdomain egress is intended.

## Source Of Truth

Use these files as the current architecture source of truth:

- `README.md`
- `docs/architecture-design.md`
- `docs/module-boundaries.md`
- `docs/threat-model.md`
- `docs/adr/*.md`
- `internal/runtime/runtime.go`
- `internal/config/config.go`
