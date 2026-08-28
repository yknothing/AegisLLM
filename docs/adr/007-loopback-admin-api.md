# ADR-007: Loopback Admin API listener

## Status
Accepted

## Context
LiteLLM ships a browser Admin UI on the proxy port. Aegis v0.2.1 kept issuance offline. Platform teams still need remote issue/revoke/usage without mounting those routes on the data-plane port.

## Decision
When `admin.enabled=true`, Aegis starts a second HTTP server. The listen address must be loopback. Authentication uses `X-Admin-Token` from `admin.token_env` with the existing constant-time compare. BYOK routes stay 501. Virtual-key issue, revoke, and usage query are mounted.

## Consequences
- New trust boundary, isolated from `/v1/chat/completions`.
- No Admin TLS in this change; bind-loopback is the compensating control.
- Operator CLI remains the offline path.
