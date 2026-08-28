# Scope judgment

Champion: Cover LiteLLM Proxy outcomes that a platform team needs on day one (chat, keys, RPM/TPM, budget, failover, four major protocols) without importing Python, Postgres, or body telemetry.

Challenger: Copying 100 providers, MCP, and the Admin UI would erase the Go/static-binary bet (ADR-005) and explode review surface. In-request fallback that rewrites ADR-004 order is also a trap; keep KMS→Adapter→Proxy order inside a retry loop.

Failure modes if the consensus is wrong:

1. Azure/Anthropic clients still break because we only transform requests and leak native response shapes.
2. TPM estimates under-count streaming and keys overspend.
3. Admin bound on `0.0.0.0` becomes a second public trust boundary without mTLS.

Decision: execute default P0. P1/P2 stay documentation. OpenRouter instead of Bedrock. Admin must be loopback.
