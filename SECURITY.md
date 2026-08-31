# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Aegis, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **security@aegisllm.dev** (or use GitHub's private vulnerability reporting feature).

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Design Principles

Aegis is built with security as the highest priority. The following invariants are enforced throughout the codebase:

### 1. No Plaintext Secrets at Rest

Provider API keys are **never** stored in plaintext — not in configuration files, databases, or command-line arguments. The offline CLI accepts provider keys only through bounded non-terminal stdin. Current runtime encrypts keys through the local AES-256-GCM KMS; v2 blobs authenticate the exact key ID as AAD. New installs use `kms.local.minimum_envelope_version=2`; version `1` is a temporary legacy-migration compatibility mode, not the steady state. HashiCorp Vault support is reserved and fails fast until implemented.

### 2. Zero PII in Logs

Audit logs record only structural metadata (timestamps, token counts, configured provider identifiers, virtual-key IDs, and status codes). Request-controlled model values are deliberately omitted together with bearer virtual keys, provider API keys, request bodies (prompts), and response bodies (completions); none of those values are logged under any circumstance.

### 3. Strong Virtual-Key Signing

HS256 virtual-key signing material must be at least 32 bytes. Aegis requires a non-empty configured issuer and an explicit supported `key_source`, rejects shorter signing keys, and rejects virtual keys whose `exp - iat` lifetime exceeds `auth.token_expiry`. Encoded virtual keys are rejected above 16 KiB before decoding or HMAC work, and the HTTP server caps total request headers at 64 KiB.

Virtual-key revocation uses a strict owner-only local snapshot. Missing, corrupt,
or permission-unsafe state prevents startup or produces a generic `503`
degraded response for otherwise valid tokens. A running reader also fails
closed if it observes a lower generation, changed content at the same
generation, or removal/shortening of any unexpired tombstone at a higher
generation. Rollback performed before process restart cannot be detected
without an independent trusted monotonic anchor; recovery must preserve the
union of unexpired tombstones. The local file backend is not supported on
shared network filesystems or as a multi-host store.

### 4. Memory Zeroing

Sensitive byte slices owned by Aegis, such as decrypted API keys and JWT signing material, are explicitly overwritten with zeros after use via `utils.MemZero()`. This reduces credential lifetime in process memory, but Go strings and crypto library internals may retain copies that Aegis cannot explicitly zero.

The validated transport limit and PII semantic input/output limit are both 4 MiB. PII additionally caps each decoded or joined text value at 512 KiB, each multimodal content array at 1 MiB, and applies explicit depth/value/member/match budgets. It tokenizes rather than materializing a full object tree. Temporary Go strings still cannot be explicitly zeroed, so the limits bound rather than eliminate that residual lifetime.

### 5. Egress Filtering

The streaming proxy engine validates configured outbound provider requests against a strict HTTPS endpoint allowlist. Exact host entries match only that host on port 443. Subdomains require an explicit `*.` wildcard entry; `*.example.com` allows nested subdomains, but not the `example.com` apex, on port 443. Non-default ports require an exact `host:port` entry. DNS names are resolved for each new connection, every answer must be public, and the transport dials only the validated IP to prevent rebinding between validation and connect. IP literals are allowed only through an explicit exact `IP:port` rule, which is intended for deliberately configured hermetic endpoints. This constrains normal proxy execution; it is not a containment boundary for a fully compromised process or malicious configuration.

### 6. Minimal Attack Surface

The production Docker image uses Google Distroless (no shell, no package manager). The binary is statically compiled with no runtime dependencies.

## Secure Development Guidelines

Contributors MUST follow these rules:

1. **Never log sensitive data**: Use the `SensitiveFields` blocklist in `internal/utils/logger.go`
2. **Always zero secrets**: Call `utils.MemZero()` or `SecureBytes.Close()` after using credentials
3. **No plaintext keys in config**: Use KMS key IDs (`api_key_id`), never raw API keys
4. **Constant-time comparison**: Use `crypto/subtle` for token/signature validation
5. **Input validation**: Reject oversized payloads, cap request-body limits, validate all user input
6. **No open redirects**: The proxy only contacts pre-configured provider URLs
7. **Strict configuration**: Reject unknown JSON fields rather than accepting misspelled security controls

Binary startup also verifies that every distinct enabled-provider `api_key_id` can be decrypted and is non-empty before reporting a runnable server. Configuration input is bounded and rejects direct symlink/non-regular paths. On supported Unix systems, local KMS blobs and TLS material additionally use non-blocking, no-follow opens and same-descriptor type, permission, and size checks.

## Dependency Policy

- Minimize external dependencies (prefer Go standard library)
- Runtime/module dependencies must be pinned by Go modules and committed in `go.sum` when present
- Release gate tools invoked through `go run module@version` must use explicit versions in `Makefile` or release scripts and are verified through the Go module checksum database
- Release gates run both source-mode and final-binary `govulncheck` scans for known vulnerabilities using the pinned release toolchain
- No dependencies with known supply chain attack history

## Supported Versions

The `v0.2.0` tag is the first supported AegisLLM release line. `v0.2.1` becomes
supported only when its tag points to a pushed commit, GitHub Actions is green,
and final release gates are recorded in
[docs/release-plan-v0.2.1.md](docs/release-plan-v0.2.1.md).

| Version | Supported |
| :--- | :---: |
| `v0.2.1` | Pending final tag and gates |
| `v0.2.0` | Yes |
| `v0.1.0` scaffold baseline | No |
