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

Audit logs record only structural metadata (timestamps, token counts, model/provider identifiers, virtual-key IDs, and status codes). Bearer virtual keys, provider API keys, request bodies (prompts), and response bodies (completions) are **never** logged under any circumstance.

### 3. Strong Virtual-Key Signing

HS256 virtual-key signing material must be at least 32 bytes. Aegis rejects shorter JWT signing keys at runtime and rejects virtual keys whose `exp - iat` lifetime exceeds `auth.token_expiry`.

### 4. Memory Zeroing

Sensitive byte slices owned by Aegis, such as decrypted API keys and JWT signing material, are explicitly overwritten with zeros after use via `utils.MemZero()`. This reduces credential lifetime in process memory, but Go strings and crypto library internals may retain copies that Aegis cannot explicitly zero.

### 5. Egress Filtering

The streaming proxy engine validates configured outbound provider requests against a domain allowlist. Exact host entries match only that host. Subdomains require an explicit `*.` wildcard entry; `*.example.com` allows nested subdomains but not the `example.com` apex. This prevents normal proxy execution from reaching non-allowlisted hosts; it is not a containment boundary for a fully compromised process or configuration.

### 6. Minimal Attack Surface

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
- Runtime/module dependencies must be pinned by Go modules and committed in `go.sum` when present
- Release gate tools invoked through `go run module@version` must use explicit versions in `Makefile` or release scripts and are verified through the Go module checksum database
- Regular `govulncheck` scans for known vulnerabilities
- No dependencies with known supply chain attack history

## Supported Versions

No stable version is supported yet. The current release candidate is `v0.2.0`,
but it must not be treated as a supported release until the release branch has
been pushed, GitHub Actions are green, and the `v0.2.0` tag has been created.
The detailed release gates are tracked in
[docs/release-plan-v0.2.0.md](docs/release-plan-v0.2.0.md).

| Version | Supported |
| :--- | :---: |
| `v0.2.0` release candidate | No |
| `v0.1.0` scaffold baseline | No |
