# ADR-004: Middleware Pipeline Order

## Status
Accepted

## Implementation Status
Current runtime enforces request-per-minute and default/per-key concurrency limits in the Rate Limit step. Token-per-minute limits are reserved; non-zero TPM configuration or claims fail closed until TPM preflight and reconciliation logic exists.

## Context
Aegis processes every request through a chain of middleware. The order of these middleware is security-critical: placing rate limiting before authentication would allow unauthenticated clients to consume rate limit capacity, while placing KMS key injection before routing would mean we don't know which key to fetch.

## Decision
The middleware pipeline will execute in this strict order:

```
1. Recovery     → Catch panics, prevent crashes
2. Request ID   → Assign tracing identifier
3. Audit Log    → Record metadata (post-request, never content)
4. Auth         → Validate Virtual Key, reject unauthorized
5. Rate Limit   → Enforce RPM/default or per-key concurrency limits; reject unsupported TPM limits
6. PII Redact   → Scan and sanitize request body
7. Router       → Select provider and model
8. KMS Inject   → Fetch and inject real API key
9. Adapter      → Transform protocol if needed
10. Proxy       → Forward to upstream provider
```

The body-processing stages share one bounded request-scoped buffer. If an adapter or redaction stage replaces that buffer, the superseded bytes are zeroed; the final buffer is zeroed when the pipeline returns. A terminal middleware commits or aborts without calling `next()`; reaching the end of the chain without a response is an internal error and fails closed.

## Rationale

The ordering follows the principle of **"fail fast, fail cheap"**:

| Position | Middleware | Why Here |
| :--- | :--- | :--- |
| 1-3 | Infrastructure | Must always run (even for rejected requests) |
| 4 | Auth | Reject unauthorized requests before any expensive work |
| 5 | Rate Limit | Prevent request-rate and default/per-key concurrency abuse before processing content; fail closed for unsupported TPM controls |
| 6 | PII | Sanitize before content leaves the gateway |
| 7 | Router | Must know the target before fetching keys |
| 8 | KMS | Fetch key only after routing decision is final |
| 9-10 | Adapter + Proxy | Actual forwarding (most expensive operation) |

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
