# ADR-006: In-request failover without reordering KMS/Adapter/Proxy

## Status
Accepted

## Context
Typical Python LLM proxies retry and fail over inside one client request. Aegis v0.2.1 selected one provider and only skipped it on later requests via the circuit breaker. ADR-004 order must stay: Router, then KMS, Adapter, Proxy.

## Decision
Router may call `next()` more than once for the same request. Each attempt still runs KMS → Adapter → Proxy in that order. Proxy suppresses writing retryable upstream failures (429, 5xx, transport errors) to the client when Router marked the attempt as fallback-capable and the response is not streaming. Canonical OpenAI-format body is restored before each attempt so a native adapter cannot poison the next provider.

Streaming requests do not fail over after the first byte.

## Consequences
- Circuit breaker still records per-attempt provider outcomes.
- Pipeline end-of-chain fail-closed ignores an uncommitted writer when `RetryableAttempt` is set; Router must abort or succeed after the last attempt.
