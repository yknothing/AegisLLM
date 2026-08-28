# Better and cheaper than a typical Python LLM proxy

Status: security, standalone TCO, and **same-box mock p95** are evidenced in this tree. See `05-bench-protocol.md` for the dated run.

## Better (security and operations)

| Claim | Why Aegis should win | Evidence |
| --- | --- | --- |
| No prompt sink | Bodies never logged; Langfuse-style prompt export is forbidden | Audit middleware + threat model; tests never capture bodies |
| Single static binary | No Python runtime, no Postgres/Redis required for standalone keys | `go test` packages and example config |
| Fail-closed policy | Unknown models have no default price; Admin is loopback-only | `internal/quota/quota_test.go`; `TestRuntimeAdminLoopbackIssueAndUsage` |
| In-request failover | Retryable 429/5xx/transport is not flushed to the client | ADR-006; `TestRuntimeInRequestFailover` |
| Credential lifetime | KMS injects after route; `SecureBytes.Close` after proxy | ADR-004 + proxy tests |
| Gateway p95 (this machine) | Go data plane vs Python proxy on the same mock | Same-box run: Aegis p95 336.833µs vs reference Python proxy 2.282375ms |

## Cheaper (standalone cost)

| Cost | Typical Python LLM proxy | Aegis standalone |
| --- | --- | --- |
| Extra datastore | Postgres/Redis for keys at scale | Local KMS files + memory limiter/quota |
| Runtime | Python + workers | One Go process |
| Body telemetry | Optional prompt sinks | Not offered |
| RSS this run | 320544 KiB proxy child | 22272 KiB test-hosted gateway (not a release binary) |

Operator spend is dominated by provider tokens. Aegis does not claim cheaper *model* tokens; it claims a cheaper *control plane* for a single host.

## Not claimed

- These p95 numbers on a different machine, payload, or reference-proxy version.
- Feature parity with 100+ providers, MCP, or a browser Admin UI.
- That Aegis RSS in this run equals a production binary (it includes `go test`).
