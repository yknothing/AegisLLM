# OpenAI-compatible gateway capability catalog

Status: Fact unless labeled. Snapshot date: 2026-08-28.

Sources: public OpenAI-compatible gateway surfaces and Aegis P0 scope. External product names and vendor URLs are omitted on purpose.

## Product split

| Product | Kind | Aegis mapping |
| --- | --- | --- |
| Python SDK (`completion()`) | SDK-only | Out of scope |
| Proxy / AI Gateway | OSS | Primary comparison target |
| Admin UI | OSS | Outcome via Admin API + Operator CLI; no pixel clone |
| Enterprise SSO/SAML | Enterprise | Out of P0; loopback Admin token is the substitute |

## Capability classes

| Class | Surface | OSS/Enterprise | Notes |
| --- | --- | --- | --- |
| Unified OpenAI API | `/chat/completions` stream+nonstream | OSS | Drop-in client `base_url` |
| Models listing | `/v1/models` | OSS | |
| Virtual keys | key/user/team budgets, RPM, TPM, model allowlists | OSS | Typical Python proxies require Postgres |
| Router | retry, fallback, load balance, cooldown | OSS | |
| Spend tracking | per key/team/user | OSS | Postgres write path in typical Python proxies |
| Guardrails / PII | masking, third-party filters | OSS + Enterprise extras | Some proxies can log bodies to callbacks |
| Caching | Redis response cache | OSS | |
| Observability | Langfuse, MLflow, Helicone | OSS | Often ships prompt/completion |
| Multi-provider | 100+ adapters | OSS | Long tail |
| Native pass-through | `/v1/messages`, Bedrock, Gemini generateContent | OSS | |
| Other endpoints | embeddings, images, audio, batches, realtime, MCP, A2A | OSS | P2 for Aegis except P0 chat |
| Admin dashboard | `/ui` | OSS | |
| Multi-tenant org tree | org/team roles | Enterprise for orgs | |

## Security side effects (Fact from docs + Aegis invariants)

Typical Python-proxy success callbacks can export request/response content. Aegis forbids logging or exporting prompt/completion bodies.
