# Changelog

All notable changes to AegisLLM are documented here.

## v0.2.1 - Unreleased

### AegisLift (OpenAI-compatible gateway outcomes)

- Added OpenAI-compatible `GET /v1/models` (virtual-key ∩ catalog).
- Enforced per-key JWT TPM (estimate then reconcile) and optional in-memory
  budgets; gateway-wide `rate_limit.default_tpm` remains a ceiling.
  Unknown models have no silent default price when quota is enabled.
- Added same-request retry/fallback (ADR-006) and same-priority weighted
  load balancing without reordering KMS → Adapter → Proxy.
- Added Azure, Anthropic, Gemini, and OpenRouter adapters.
- Mounted loopback Admin issue/revoke/usage (ADR-007). BYOK stays 501.
- Operator `virtual-key issue` accepts `--tpm` and `--budget`.
- Added runtime evidence: in-request failover, SSE chat, loopback Admin
  issue, Anthropic/Gemini response transforms, unknown-model
  quota fail-closed.
- Recorded a same-box mock-upstream overhead run against a reference Python
  LLM proxy; Aegis p95 was not worse. See `docs/aegis-lift/05-bench-protocol.md`.
- Same-priority weighted pick draws from `crypto/rand` (not `math/rand`).
- Documented that the Gemini `x-goog-api-key` constant is a header name,
  not a stored credential.
- Removed third-party LLM proxy product names from public docs and changelog.

### Standalone operations and security

- Added a same-binary offline Operator CLI for revocation initialization,
  configured provider-key import, pool virtual-key issuance/revocation, and KMS
  migration inspection/application.
- Restricted provider-key input to bounded non-terminal stdin and required
  explicit token output to either stdout or a new owner-only file.
- Added a versioned local-KMS envelope that authenticates the exact key ID as
  AES-GCM AAD, supports a bounded legacy compatibility migration from a
  complete encrypted backup, and enforces a strict-v2 post-migration floor.
- Replaced runtime process-memory revocation with a strict versioned local
  snapshot, serialized atomic writer, bounded polling reader, immutable request
  lookup, fail-closed corruption/deletion behavior, and running-reader rollback
  detection; cross-restart rollback remains an explicit single-file limitation.
- Unified HS256 virtual-key issuance and validation in one internal contract and
  aligned the default maximum token lifetime to 24 hours.
- Bounded bearer/header sizes, `issuer`/`kid` revocability, token lifetime
  arithmetic, mandatory positive RPM/concurrency defaults, and exact model-key
  JSON semantics so accepted credentials and policy decisions remain
  revocable and fail closed.
- Reworked PII handling as bounded semantic JSON tokenization: escaped values,
  duplicate or case-ambiguous members, numeric/key PII, overlapping matches,
  and PII split across text parts are handled without materializing an
  unbounded object tree. The config and semantic request ceiling is now 4 MiB.
- Hardened HTTPS egress with exact host/port policy, userinfo/fragment refusal,
  fail-closed DNS resolution against current public-address allocations,
  validated-IP dialing with preserved TLS SNI, and redirect refusal.
- Added startup decryption probes for every distinct enabled-provider
  credential, with immediate secure-byte closure and generic failures.
- Hardened config, TLS, KMS, revocation, migration, and release-evidence file
  reads against symlink/FIFO/device races, unsafe permissions, and unbounded
  input; shutdown now drains or terminates handlers before resource teardown
  and bounds shutdown hooks.
- Made circuit-breaker half-open decisions generation-bound, preserved the
  actual committed client status in audit records, and guaranteed completion
  audit metadata even when recovered middleware panics.
- Extended local and Mac Mini Docker smoke contracts to initialize durable
  revocation state and exercise the release binary's offline provisioning path.
- Added exact-SHA/dirty-evidence labeling, strict external release-manifest and
  post-publication closure schemas, and a Linux-only sealed-binary migration/
  rollback drill runner. These tools validate structure and byte bindings but
  deliberately do not replace independent human governance or external trust.
- Updated the pinned Go quality/Docker toolchain from 1.26.5 to 1.26.6.

## v0.2.0 - 2026-06-21

### Security hardening

- Added fail-fast validation for reserved runtime controls: Vault KMS, Redis rate limiter, quota enforcement, provider TPM, provider RPM, default TPM, and unsupported provider adapters.
- Added fail-fast validation for out-of-range server runtime bounds: read timeout, write timeout, shutdown timeout, and max request body size with an explicit 64 MiB configuration ceiling.
- Added `max_concurrency` virtual-key claim support so subscription-tier concurrency limits can be enforced by the in-memory rate limiter; negative concurrency claims fail closed, and the non-zero default is the policy ceiling applied independently to each key.
- Validated reserved and invalid rate-limit fields even when rate limiting is disabled, so disabled Redis/TPM settings cannot remain in accepted configs.
- Removed reserved TPM token-accounting state from the `v0.2.0` runtime so token counts are not retained until TPM enforcement is implemented.
- Removed the old `v0.1.0` scaffold-style Redis, Vault, quota, and store defaults from the example config and rejected reserved Redis URL, Vault config, quota backend, quota DSN, quota default-budget, and store config fields in the `v0.2.0` runtime truth surface.
- Changed virtual-key model authorization to fail closed when the `models` claim is missing or empty. Use explicit `"*"` for all-model access.
- Enforced a minimum HS256 JWT signing-key length, maximum virtual-key lifetime from `auth.token_expiry`, and generic authentication failure responses.
- Hardened the reserved Admin API scaffold so admin token failures return a generic response, provided-token comparisons reach a fixed-length hash comparison path, and the scaffold health route also requires the admin token.
- Rejected reserved `key_source="byok"` virtual keys until server-side BYOK owner/provider binding exists.
- Rejected negative rate-limit configuration values instead of treating them as unlimited.
- Tightened proxy egress validation to require HTTPS, enforced TLS 1.3 for upstream connections, and changed upstream request header forwarding to a minimal allowlist.
- Changed egress allowlist host matching to exact-host by default; subdomain egress now requires an explicit `*.` wildcard entry.
- Validated client-supplied `X-Request-ID` before echoing it; unsafe, oversized, or malformed IDs are replaced with generated request IDs, and safe upstream provider request IDs are mapped to `X-Upstream-Request-Id` instead of overwriting the gateway request ID.
- Renamed audit metadata from `virtual_key` to `virtual_key_id` and redacted any accidental `virtual_key` log field so bearer virtual keys cannot be logged under the ambiguous field name.
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
- Removed the disabled Anthropic placeholder and unused `api.anthropic.com` egress entry from the example/Docker default config so the default allowlist matches enabled runtime providers.
- Updated Docker builds to use target platform arguments so the compiled binary architecture matches the image architecture.
- Added `.dockerignore` to keep VCS metadata, local secrets, key stores, coverage, and scratch files out of Docker build contexts.
- Pinned Makefile-installed security tooling versions.
- Added CI for Go 1.22 compatibility, Go 1.26 quality gates, and Docker read-only smoke testing with pinned official GitHub Actions.
- Raised the bounded SSE scanner line limit so large provider stream events above Go's default scanner token size can be forwarded without making stream parsing unbounded.

### Documentation

- Marked `v0.2.0` as the remediated architecture truth surface superseding the `v0.1.0` scaffold baseline.
- Documented current runtime capabilities versus planned capabilities across README, architecture docs, ADRs, and integration notes.
- Clarified local KMS memory-zeroing and egress allowlist residual risks without claiming impossible Go runtime guarantees.
- Recorded that Admin API issuance, Vault KMS, Redis rate limiting, quota/TPM enforcement, RS256, and non-OpenAI protocol adapters remain planned work.
- Aligned subscription templates, app integration examples, Router comments, Vault scaffold comments, and release evidence docs with the current `v0.2.0` runtime truth surface.

### Required verification gates before tag

- `make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local`
- `make local-smoke GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local COMMIT=<candidate-sha> PORT=<free-port>`
- `make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=<candidate-sha> BUILD_DATE=<utc-build-date> PORT=<free-port>`
- GitHub Actions CI on the final pushed SHA before tag creation
- `actionlint`
- Mac mini Docker build and read-only container `/health` smoke
