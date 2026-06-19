# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Aegis, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **security@aegisllm.dev** (or use GitHub's private vulnerability reporting feature).

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Design Principles

Aegis is built with security as the highest priority. The following invariants are enforced throughout the codebase:

### 1. No Plaintext Secrets at Rest

Provider API keys are **never** stored in plaintext — not in configuration files, not in databases, not in environment variables (except the master encryption key). Current runtime encrypts keys through the local AES-256-GCM KMS. HashiCorp Vault support is reserved and fails fast until implemented.

### 2. Zero PII in Logs

Audit logs record only structural metadata (timestamps, token counts, model names, status codes). Request bodies (prompts) and response bodies (completions) are **never** logged under any circumstance.

### 3. Memory Zeroing

Sensitive data (decrypted API keys, JWT signing material) is explicitly overwritten with zeros after use via `utils.MemZero()`. This prevents credential recovery from memory dumps.

### 4. Egress Filtering

The streaming proxy engine validates all outbound requests against a configured domain allowlist. Even if the gateway is compromised, it cannot exfiltrate data to unauthorized endpoints.

### 5. Minimal Attack Surface

The production Docker image uses Google Distroless (no shell, no package manager). The binary is statically compiled with no runtime dependencies.

## Secure Development Guidelines

Contributors MUST follow these rules:

1. **Never log sensitive data**: Use the `SensitiveFields` blocklist in `internal/utils/logger.go`
2. **Always zero secrets**: Call `utils.MemZero()` or `SecureBytes.Close()` after using credentials
3. **No plaintext keys in config**: Use KMS key IDs (`api_key_id`), never raw API keys
4. **Constant-time comparison**: Use `crypto/subtle` for token/signature validation
5. **Input validation**: Reject oversized payloads, validate all user input
6. **No open redirects**: The proxy only contacts pre-configured provider URLs

## Dependency Policy

- Minimize external dependencies (prefer Go standard library)
- All dependencies must be pinned to exact versions in `go.sum`
- Regular `govulncheck` scans for known vulnerabilities
- No dependencies with known supply chain attack history

## Supported Versions

No stable version is supported yet. The current release candidate is `v0.2.0`,
but it must not be treated as a supported release until the release branch has
been pushed, GitHub Actions are green, and the `v0.2.0` tag has been created.

| Version | Supported |
| :--- | :---: |
| `v0.2.0` release candidate | No |
| `v0.1.0` scaffold baseline | No |
