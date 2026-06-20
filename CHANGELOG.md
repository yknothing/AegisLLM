# Changelog

All notable changes to AegisLLM are documented here.

## v0.2.0 - Release Candidate

### Security hardening

- Added fail-fast validation for reserved runtime controls: Vault KMS, Redis rate limiter, quota enforcement, provider TPM, provider RPM, default TPM, and unsupported provider adapters.
- Validated reserved and invalid rate-limit fields even when rate limiting is disabled, so disabled Redis/TPM settings cannot remain in accepted configs.
- Removed the old `v0.1.0` scaffold-style Redis, Vault, quota, and store defaults from the example config and rejected reserved Redis URL, Vault config, quota backend, quota DSN, quota default-budget, and store config fields in the `v0.2.0` runtime truth surface.
- Changed virtual-key model authorization to fail closed when the `models` claim is missing or empty. Use explicit `"*"` for all-model access.
- Enforced a minimum HS256 JWT signing-key length, maximum virtual-key lifetime from `auth.token_expiry`, and generic authentication failure responses.
- Rejected reserved `key_source="byok"` virtual keys until server-side BYOK owner/provider binding exists.
- Rejected negative rate-limit configuration values instead of treating them as unlimited.
- Tightened proxy egress validation to require HTTPS, enforced TLS 1.3 for upstream connections, and changed upstream request header forwarding to a minimal allowlist.
- Restricted adapter-generated provider target paths to root-relative paths so plugin or adapter errors cannot override the configured provider authority before proxy egress validation.
- Changed upstream response header forwarding to an explicit client-contract allowlist for content type, request IDs, rate-limit metadata, and retry hints.
- Filtered unsafe upstream response headers so hop-by-hop and credential-bearing provider headers are not reflected to clients.
- Removed the unused `MemZeroString` API because mutating Go string backing memory is unsafe.
- Removed key identifiers from reserved Vault backend error messages.
- Hardened audit log redaction so sensitive top-level fields, nested `slog.Group` fields, resolved `slog.LogValuer` groups, and `WithAttrs` context values are redacted before output while preserving structural token-count metadata.

### Runtime and packaging

- Added a local encrypted file-backed KMS backend for standalone validation.
- Added a runtime composition root that wires the middleware pipeline in the ADR-004 order.
- Added Docker image defaults for `/etc/aegis/aegis.json` and `/var/lib/aegis`.
- Updated Docker builds to use target platform arguments so the compiled binary architecture matches the image architecture.
- Added `.dockerignore` to keep VCS metadata, local secrets, key stores, coverage, and scratch files out of Docker build contexts.
- Pinned Makefile-installed security tooling versions.
- Added CI for Go 1.22 compatibility, Go 1.26 quality gates, and Docker read-only smoke testing with pinned official GitHub Actions.

### Documentation

- Marked `v0.2.0` as the remediated architecture truth surface superseding the `v0.1.0` scaffold baseline.
- Documented current runtime capabilities versus planned capabilities across README, architecture docs, ADRs, and integration notes.
- Clarified local KMS memory-zeroing and egress allowlist residual risks without claiming impossible Go runtime guarantees.
- Recorded that Admin API issuance, Vault KMS, Redis rate limiting, quota/TPM enforcement, RS256, and non-OpenAI protocol adapters remain planned work.

### Verification evidence

- `go test ./...`
- `go vet ./...`
- `go test -race ./...`
- `golangci-lint`
- `govulncheck`
- `gosec`
- `actionlint`
- Local process `/health` smoke
- Mac mini Docker build and read-only container `/health` smoke
