# Published Python LLM proxy performance and operations

Status: Hypothesis until reproduced on the same hardware. Snapshot date: 2026-08-28.

Source: public Python LLM-proxy benchmark and production sizing notes. Vendor URLs are omitted on purpose.

## Published gateway numbers (Hypothesis)

| Claim | Value | Conditions |
| --- | --- | --- |
| Overhead P95 | 8 ms | 4 instances, Locust 1000 users, 0.5–1s think time |
| Instance size | 4 CPU / 8 GB | Fake OpenAI endpoint, Postgres, Redis unused in the published run |
| Production floor | 1 vCPU / 4 Gi per worker | K8s: one Uvicorn worker per pod |
| Virtual keys | Postgres required | Auth cached; spend writes dominate |
| Multi-instance | Redis required | Rate limit, cache, spend buffer |

## Cost structure vs Aegis target

| Item | Typical Python LLM proxy | Aegis P0 target |
| --- | --- | --- |
| Single-host deps | Python runtime + Postgres for keys | One static binary + local KMS file |
| Memory | Documented growth; worker recycle | No recycle policy |
| Token spend from health checks | Duplicate probes across pods unless Redis lock | Circuit breaker uses proxy-observed 429/5xx only |
| Body telemetry | Optional callbacks with content | Forbidden |

Reproduction protocol lives in `05-bench-protocol.md`. Until that run exists, published 8 ms P95 is not acceptance evidence.
