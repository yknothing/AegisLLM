# ADR-002: Dual-Layer KMS Architecture

## Status
Accepted

## Implementation Status
Current runtime implements the local AES-256-GCM KMS with in-memory and encrypted file backends. New v2 blobs authenticate their exact key ID as AAD; legacy blobs remain readable and can be migrated explicitly from a complete encrypted backup. `kms.mode: "vault"` is reserved and fails fast.

## Context
Aegis must store provider API keys securely at rest. Different deployment environments have different capabilities: a solo developer running Aegis locally cannot be expected to operate a HashiCorp Vault cluster, while an enterprise deployment demands integration with existing secrets infrastructure.

## Decision
We will implement a **dual-layer KMS** with a unified `kms.Provider` interface:

1. **Local Layer (Built-in)**: AES-256-GCM encryption using a master key from an environment variable. The v2 envelope authenticates format metadata and key identity; file replacement is atomic. Encrypted blobs are stored in memory for tests or local files for standalone deployments.
2. **Vault Layer (External)**: Delegates all key operations to HashiCorp Vault (or compatible systems like AWS Secrets Manager). This is a reserved enterprise deployment target, not current runtime behavior.

Both layers share the same `kms.Provider` interface. The current supported runtime choice is `kms.mode: "local"`; `kms.mode: "vault"` is rejected until the Vault client and failure-mode tests are implemented.

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
