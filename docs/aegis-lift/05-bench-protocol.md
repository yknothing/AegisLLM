# AegisLift bench protocol

## Purpose

Compare Aegis proxy overhead with a reference Python LLM proxy on the same OpenAI-compatible chat path, without treating marketing numbers as evidence.

## Required fixtures

- Same machine, same Go/Python process pinning, same payload bytes.
- Local mock upstream that returns a fixed 200 JSON body. Do not call billed providers.
- Aegis: `POST /v1/chat/completions` with a pool virtual key.
- Reference Python proxy: equivalent `/v1/chat/completions` against the same mock.

## Metrics

| Metric | How to collect |
| --- | --- |
| p50 / p95 / p99 gateway added latency | Client timestamps for sequential RTT against a shared mock |
| Success rate | HTTP 200 / total |
| RSS | `ps -o rss=` after warmup |
| CPU | `sample` or `perf` over the same window |

## Pass rule

Aegis p95 overhead is not worse than the reference Python proxy number collected in the **same run**. If that proxy was not started in that run, the comparison is **Hypothesis** and must not be reported as a pass.

## Forbidden

- Hitting OpenAI, Anthropic, Azure, Gemini, or OpenRouter with a real key for a bench.
- Logging request or response bodies.
- Publishing numbers from a different machine or payload as this protocol's result.
- Naming third-party products in this tree's docs, changelog, or commit messages.

## Same-box run (2026-08-28)

The reference Python proxy was installed into an isolated venv (pinned OSS proxy extras) and driven by a local optional test that is skipped in CI when the proxy binary env is unset.

`-race` was not set. Both gateways used one `httptest` TLS 1.3 mock that returned a fixed OpenAI chat JSON with one choice. The reference proxy `api_base` was that mock plus `/v1`, TLS verify off, retries `0`. Process SOCKS/HTTP proxy env vars were stripped so the child could not leave loopback. Warmup 20, samples 200, sequential.

| Field | Aegis | Reference Python LLM proxy |
| --- | --- | --- |
| Collected at (UTC) | 2026-08-28T01:28:01Z | same run |
| Host | darwin arm64, Darwin 27.0.0, go1.26.4 | same |
| Success rate | 1.0 | 1.0 |
| p50 | 219.875µs | 2.070875ms |
| p95 | 336.833µs | 2.282375ms |
| p99 | 547.375µs | 2.486416ms |
| RSS (`ps` KiB) | 22272 (Go test process hosting the gateway) | 320544 (proxy child) |
| Protocol pass | **true** (Aegis p95 is not worse) | — |

### Caveats

- Aegis RSS is the `go test` process, not a stripped release binary. The other RSS is the Python proxy process.
- Aegis still ran JWT auth, PII, and in-memory rate limit. The reference proxy ran without a master-key gate.
- Client RTT includes mock TLS. The mock handler is local and negligible next to either gateway.
- CPU sampling over 60s was not collected in this run.
- The optional same-box test skips when the reference-proxy binary env is unset so CI does not require Python.
