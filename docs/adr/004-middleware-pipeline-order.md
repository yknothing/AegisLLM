# ADR-004: Middleware Pipeline Order

## Status
Accepted

## Implementation Status
Current runtime enforces request-per-minute, optional token-per-minute, and default/per-key concurrency limits in the Rate Limit step. When `quota.enabled=true`, a Quota step runs after Rate Limit and before PII. Router may retry `next()` for failover (ADR-006) without changing this order.

## Context
Aegis processes every request through a chain of middleware. The order of these middleware is security-critical: placing rate limiting before authentication would allow unauthenticated clients to consume rate limit capacity, while placing KMS key injection before routing would mean we don't know which key to fetch.

## Decision
The middleware pipeline will execute in this strict order:

```
1. Recovery     → Catch panics, prevent crashes
2. Request ID   → Assign tracing identifier
3. Audit Log    → Record metadata (post-request, never content)
4. Auth         → Validate Virtual Key, reject unauthorized
5. Rate Limit   → Enforce RPM/TPM and default/per-key concurrency limits
6. Quota        → Optional in-memory budget check and post-request cost record
7. PII Redact   → Scan and sanitize request body
8. Router       → Select provider and model; may retry inner steps on failover
9. KMS Inject   → Fetch and inject real API key
10. Adapter     → Transform protocol if needed
11. Proxy       → Forward to upstream provider
```

The pipeline acquires one bounded transport body. PII validates it token by token under tighter semantic byte, string, content-array, depth, value, member, and match ceilings and may emit one bounded canonical replacement buffer; router and adapter reuse the resulting owned body. If an adapter or redaction stage replaces that buffer, the superseded bytes are zeroed; the final buffer is zeroed when the pipeline returns. A terminal middleware commits or aborts without calling `next()`; reaching the end of the chain without a response is an internal error and fails closed.

## Rationale

The ordering follows the principle of **"fail fast, fail cheap"**:

| Position | Middleware | Why Here |
| :--- | :--- | :--- |
| 1-3 | Infrastructure | Must always run (even for rejected requests) |
| 4 | Auth | Reject unauthorized requests before any expensive work |
| 5 | Rate Limit | Prevent request-rate, token-rate, and default/per-key concurrency abuse before processing content |
| 6 | Quota | Optional fail-closed budget check before PII and egress; record cost after the inner chain returns |
| 7 | PII | Sanitize before content leaves the gateway |
| 8 | Router | Must know the target before fetching keys; may retry inner steps on failover |
| 9 | KMS | Fetch key only after routing decision is final |
| 10-11 | Adapter + Proxy | Actual forwarding (most expensive operation) |

## Consequences

### Positive
- Unauthorized requests are rejected at step 4 with minimal resource consumption.
- Rate-limited requests are rejected at step 5 without touching KMS or providers.
- PII is redacted before any routing or key injection occurs.
- The real API key exists in memory for the shortest possible duration (steps 8-10 only).
- Provider health is updated only from proxy-observed provider outcomes; local gateway failures remain outside the circuit-breaker signal.

### Negative
- The strict ordering means middleware cannot be freely reordered without security review.
- Adding new middleware requires careful consideration of where it fits in the security hierarchy.
