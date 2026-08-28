# LiteLLM Proxy capability catalog

Status: Fact unless labeled. Snapshot date: 2026-08-28.

Sources:

- https://docs.litellm.ai/docs/
- https://docs.litellm.ai/docs/supported_endpoints
- https://docs.litellm.ai/docs/benchmarks
- https://docs.litellm.ai/docs/proxy/prod
- https://github.com/BerriAI/litellm

## Product split

| Product | Kind | Aegis mapping |
| --- | --- | --- |
| Python SDK (`completion()`) | SDK-only | Out of scope |
| Proxy / AI Gateway | OSS | Primary competitor |
| Admin UI | OSS | Outcome via Admin API + Operator CLI; no pixel clone |
| Enterprise SSO/SAML | Enterprise | Out of P0; loopback Admin token is the substitute |

## Capability classes

| Class | Surface | OSS/Enterprise | Notes |
| --- | --- | --- | --- |
| Unified OpenAI API | `/chat/completions` stream+nonstream | OSS | Drop-in client `base_url` |
| Models listing | `/v1/models` | OSS | |
| Virtual keys | key/user/team budgets, RPM, TPM, model allowlists | OSS | Needs Postgres in LiteLLM |
| Router | retry, fallback, load balance, cooldown | OSS | |
| Spend tracking | per key/team/user | OSS | Postgres write path |
| Guardrails / PII | masking, third-party filters | OSS + Enterprise extras | LiteLLM can log bodies to callbacks |
| Caching | Redis response cache | OSS | |
| Observability | Langfuse, MLflow, Helicone | OSS | Often ships prompt/completion |
| Multi-provider | 100+ adapters | OSS | Long tail |
| Native pass-through | `/v1/messages`, Bedrock, Gemini generateContent | OSS | |
| Other endpoints | embeddings, images, audio, batches, realtime, MCP, A2A | OSS | P2 for Aegis except P0 chat |
| Admin dashboard | `/ui` | OSS | |
| Multi-tenant org tree | org/team roles | Enterprise for orgs | |

## Security side effects (Fact from docs + Aegis invariants)

LiteLLM success callbacks can export request/response content. Aegis forbids logging or exporting prompt/completion bodies.
