# AegisLift gap matrix

Legend: P0 this change-set; P1 later; P2 deferred; Out excluded.

| Capability | Typical Python LLM proxy | Aegis before | Target | Priority | After this change-set |
| --- | --- | --- | --- | --- | --- |
| Chat completions stream+nonstream | Yes | Yes | Keep | P0 | Yes; SSE e2e `TestRuntimeChatSSE` |
| `GET /v1/models` | Yes | No | Auth + intersection of key and catalog | P0 | Yes; hermetic + Admin-issued key |
| Virtual key RPM/concurrency | Yes | Yes | Keep | P0 | Yes |
| Virtual key TPM | Yes | Reject | Memory sliding window + estimate/reconcile | P0 | Yes |
| Key budget fail-closed | Yes | Reject | Memory quota + JWT/config budget | P0 | Yes; `quota_test.go` unknown model |
| Retry + in-request fallback | Yes | Circuit only | Same-request next channel on 429/5xx/transport | P0 | Yes; `TestRuntimeInRequestFailover` |
| Weighted LB | Yes | Deterministic weight | Weighted pick among same priority | P0 | Yes; `TestPickWeightedPrefersHeavierChannel` |
| Anthropic Messages adapter | Yes | Stub error | Request/response/stream transform | P0 | Yes; response + stream-line tests |
| Azure OpenAI adapter | Yes | No | Path + `api-key` | P0 | Yes; deployment path test |
| Gemini generateContent | Yes | Stub error | Request transform + API key header | P0 | Yes; response transform test |
| OpenRouter | Yes | No | OpenAI-compatible type | P0 | Yes; adapter path test |
| Admin issue/revoke/usage | UI | Offline CLI | Loopback HTTP Admin | P0 | Yes; `TestRuntimeAdminLoopbackIssueAndUsage` |
| Precise cost | Pricing map | Heuristic only | Table + optional config prices | P0 | Yes; unknown models fail closed |
| 100+ providers | Yes | 2 | OpenAI-compatible generic only | Out | Out |
| Python SDK | Yes | No | Never | Out | Out |
| MCP / A2A / realtime | Yes | No | Later | P2 | P2 |
| Prompt sinks (Langfuse body) | Yes | Forbidden | Keep forbidden | Out | Forbidden |
| Postgres/Redis standalone | Required for keys | Not required | Keep optional/reserved | Out | Still unused |
| Bedrock SigV4 | Yes | No | OpenRouter chosen instead | P2 | P2 |
| Redis limiter | Yes | Fail-fast | Still reserved | P1 | Reserved |
| Team/org tree | Yes | No | Later | P1 | P1 |
