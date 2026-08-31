# Aegis runtime truth (pre-AegisLift)

Status: Historical snapshot from before AegisLift wiring. Current status is `docs/aegis-lift/03-gap-matrix.md` plus `ARCHITECTURE.md`.

| Capability | Runtime | Evidence |
| --- | --- | --- |
| `POST /v1/chat/completions` | Yes | `internal/server/server.go` |
| `GET /health` | Yes | same |
| `GET /v1/models` | No | mux mounts only chat + health |
| HS256 virtual keys | Yes | `internal/virtualkey` |
| TPM / budget claims | Rejected | `validateClaims` |
| RPM + concurrency | Yes, memory | `internal/middleware/ratelimit.go` |
| Same-model priority routing | Yes | `router.go`; weight is a deterministic tie-break |
| In-request fallback/retry | No | one `Route()` per request |
| Weighted load balance | No | highest weight wins |
| openai / deepseek | Yes | `isSupportedProviderType` |
| anthropic / google / azure / openrouter | Fail-closed | adapters stubbed or types rejected |
| Local KMS | Yes | AES-GCM v2 |
| Quota | Scaffold only | `quota.enabled=true` fails load |
| Admin API | Unmounted 501 scaffold | `internal/admin` |
| Streaming proxy | Yes | heuristic token count |
| PII | Yes | lexical JSON |
| Body logs | Forbidden | `AuditMiddleware` |
