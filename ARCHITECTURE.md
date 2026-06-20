# AegisLLM Architecture Truth Surface

## Version

| Field | Value |
| --- | --- |
| Architecture version | `v0.2.0` |
| Supersedes | `v0.1.0` legacy architecture scaffold |
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

The main gateway mounts only `/v1/*` and `/health`. Admin routes exist as a scaffold in `internal/admin` but are not mounted by `cmd/aegis`.

## Implemented Baseline

| Capability | Runtime status |
| --- | --- |
| Auth | HS256 virtual-key validation, issuer/expiry checks, process-local revocation store |
| Rate limiting | In-memory RPM and concurrency |
| PII | Default regex redaction mode |
| Routing | Enabled provider selection by model, priority, and circuit-breaker state |
| KMS | Local AES-256-GCM with in-memory and encrypted file backends |
| Providers | OpenAI-compatible `openai` and `deepseek` request path |
| Proxy | SSE forwarding, egress allowlist validation, heuristic token counting |
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

Container smoke runs can use the bundled `/etc/aegis/aegis.json`. Production container deployments should mount `/etc/aegis/aegis.json` explicitly and must provide a writable `/var/lib/aegis` volume when using file-backed local KMS.

## Source Of Truth

Use these files as the current architecture source of truth:

- `README.md`
- `docs/architecture-design.md`
- `docs/module-boundaries.md`
- `docs/threat-model.md`
- `docs/adr/*.md`
- `internal/runtime/runtime.go`
- `internal/config/config.go`
