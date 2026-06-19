# ADR-001: Virtual Key as Universal Access Token

## Status
Accepted

## Implementation Status
Current runtime implements HS256 validation, model permissions, RPM claims, and a process-local in-memory revocation store. Non-zero TPM and budget claims fail closed until enforcement exists. RS256, Redis-backed revocation, and admin-driven revocation are accepted target capabilities, not current runtime capabilities.

## Context
Aegis needs a mechanism to authenticate clients, enforce rate limits, track budgets, and authorize model access. Passing real provider API keys (like OpenAI keys) directly from clients is insecure and makes quota management impossible. We need an abstraction layer.

## Decision
We will use **Virtual Keys** implemented as signed JSON Web Tokens (JWT).

1. All client requests must include an `Authorization: Bearer <virtual_key>` header.
2. The Virtual Key encapsulates the client's identity (`sub`), permissions (`models`), and limits. Current runtime enforces `rpm`; `tpm` and `budget` are reserved claims that must be zero until enforcement exists.
3. Aegis validates the signature cryptographically without needing a database lookup for every request.
4. Revocation is handled via a revocation store checking the key ID (`kid`). The current runtime store is process-local memory; Redis-backed shared revocation is reserved for cluster mode.

## Consequences

### Positive
- **Stateless Validation**: The auth middleware can validate requests instantly without hitting a database.
- **Granular Control**: Limits are embedded directly in the token.
- **Security Isolation**: If a Virtual Key is leaked, the real provider API key remains safe. The Virtual Key can be revoked instantly.

### Negative
- **Token Size**: JWTs are larger than simple opaque strings (like standard API keys).
- **Revocation Complexity**: Stateless tokens require a separate revocation list infrastructure to handle early termination.

## Implementation Details

The current JWT implementation uses HS256. The signing key is held in memory by Aegis and explicitly zeroed on shutdown. RS256 requires a reviewed key-loading and rotation boundary before it is enabled.
