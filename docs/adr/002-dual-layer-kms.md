# ADR-002: Dual-Layer KMS Architecture

## Status
Accepted

## Context
Aegis must store provider API keys securely at rest. Different deployment environments have different capabilities: a solo developer running Aegis locally cannot be expected to operate a HashiCorp Vault cluster, while an enterprise deployment demands integration with existing secrets infrastructure.

## Decision
We will implement a **dual-layer KMS** with a unified `kms.Provider` interface:

1. **Local Layer (Built-in)**: AES-256-GCM encryption using a master key from an environment variable. Encrypted blobs stored in SQLite or memory. Suitable for development and small-team deployments.
2. **Vault Layer (External)**: Delegates all key operations to HashiCorp Vault (or compatible systems like AWS Secrets Manager). Suitable for enterprise deployments.

Both layers implement the same `kms.Provider` interface. The choice is a single configuration toggle (`kms.mode: "local" | "vault"`).

## Consequences

### Positive
- **Progressive Security**: Teams can start with local KMS and upgrade to Vault without code changes.
- **Interface Stability**: All middleware that consumes keys depends only on the abstract `kms.Provider` interface.
- **Defense in Depth**: Even the local layer provides meaningful protection against config file theft and database exposure.

### Negative
- **Local Layer Limitations**: Cannot protect against root-level memory inspection of the running process.
- **Master Key Bootstrap**: The local layer requires a master key in an environment variable, which itself must be protected by the deployment platform.

## Security Properties

| Property | Local Layer | Vault Layer |
| :--- | :--- | :--- |
| Encryption at rest | AES-256-GCM | Vault-managed |
| Key rotation | Manual (re-encrypt) | Native versioning |
| Audit trail | Application logs | Vault audit backend |
| Memory protection | MemZero after use | MemZero after use |
| Network exposure | None (local) | TLS to Vault server |
