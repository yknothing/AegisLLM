# AegisLLM Architecture Refactor Progress

## Objective

Refactor until the architecture is coherent and evidence-backed. After each significant step: live-test, run autoreview, and commit.

## Baseline

- Branch: `codex/aegis-architecture-refactor`
- Starting HEAD: `4864cb8 feat: implement hybrid key source resolution (ADR-003)`
- Current state: architecture/runtime framework changes are committed on `codex/aegis-architecture-refactor`.
- Tooling note: system `PATH` still has no `go` or `gofmt`; verification uses `$HOME/.cache/codex-go/go1.26.4/bin`.

## Step Log

### Step 0 - Baseline Capture

- Created progress tracker.
- Confirmed current worktree has uncommitted architecture framework changes.
- Confirmed project `tmp/` is ignored, so this file must be force-added when committing.

### Step 1 - Runtime Architecture Framework

- Added architecture design, module-boundary, and threat-model documents.
- Added `internal/runtime` as the composition root so `internal/server` remains a microkernel.
- Wired the main runtime pipeline: auth, rate limit, PII redaction, router, KMS, adapter, proxy.
- Added bounded body helpers, HS256 virtual-key validation, model parsing, egress host validation, terminal proxy middleware, and shutdown hooks.
- Updated README implementation status to distinguish implemented baseline from unsupported production tracks.
- Installed local Go toolchains in `$HOME/.cache/codex-go` for verification. Go 1.22.4 compiled packages but test binaries failed on macOS 27 with `missing LC_UUID load command`; Go 1.26.4 was used for current verification.
- Live-test: started the gateway with a smoke config, verified `/health` returns `{"status":"ok"}` and unauthenticated `/v1/chat/completions` returns `401`.
- Autoreview fix: changed egress allowlist from implicit provider-host derivation to explicit fail-fast config validation.
- Autoreview fix: disabled unsafe half-implemented provider paths; enabled provider types are limited to the current OpenAI-compatible baseline (`openai`, `deepseek`) and the sample Anthropic provider is disabled.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go vet ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race ./...` passed.
  - `git diff --check` passed.
  - Live-test verified `/health` = 200, unauthenticated `/v1/chat/completions` = 401, valid JWT with missing provider key = 503.

### Step 2 - Truth Surface and Admin Fail-Closed Cleanup

- Changed Admin BYOK mutation endpoints to fail closed with `501` instead of storing a key and returning `vk_placeholder`.
- Added admin tests proving missing admin auth is rejected and BYOK registration does not call KMS while unimplemented.
- Updated README capability and deployment sections to distinguish implemented baseline from planned Vault, Redis, quota, persistent KMS, Admin, and non-OpenAI adapter work.
- Updated Quick Start into a development smoke path and marked SDK usage as the intended interface after key issuance/provider-key seeding exists.
- Live-test: started the gateway and verified `/health` returns `{"status":"ok"}` and a valid JWT request fails at KMS with `503` when no provider key is seeded.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go vet ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race ./...` passed.
  - `git diff --check` passed.

### Step 3 - Local KMS File Backend

- Added a local encrypted file backend for KMS blobs. The backend stores only nonce+ciphertext+GCM tag under base64url-encoded filenames.
- Added `kms.local.key_store_path` config and runtime wiring. Empty path keeps the in-memory backend for smoke tests.
- Added tests for file permissions, persistence across store reopens, list/delete behavior, config parsing, and runtime backend selection.
- Updated README and architecture docs to reflect that standalone validation can use an encrypted file KMS store.
- Live-test: started the gateway with `key_store_path=tmp/aegis-smoke-keys`, verified `/health` = 200, valid JWT with missing provider key = 503, and key-store directory mode = 700.
- Autoreview: checked that the new backend receives encrypted blobs only, uses encoded filenames, keeps runtime plaintext-key config out of scope, and is covered by persistence/permission tests.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go vet ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race ./...` passed.
  - `git diff --check` passed.

## Final Completion Audit

- Branch contains three implementation commits:
  - `ee55d1d refactor: wire secure runtime architecture baseline`
  - `e36e31f refactor: make admin scaffold fail closed`
  - `8b33eaf refactor: add encrypted local KMS file backend`
- Current architecture state:
  - `internal/server` remains the HTTP/pipeline microkernel.
  - `internal/runtime` is the composition root and owns concrete middleware wiring.
  - Unsupported production tracks are documented and fail closed instead of silently running.
  - Local KMS supports smoke-test memory storage and encrypted file-backed standalone storage.
- Final verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go vet ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race ./...` passed.
  - Final live-test using `/tmp/aegis-final-smoke.json` verified `/health` = 200, valid JWT with missing provider key = 503, and file KMS directory mode = 700.
- Remaining planned capabilities are explicit non-goals for this refactor slice: Vault KMS, Redis limiter, TPM enforcement, quota runtime enforcement, Admin issuance/revocation/storage flows, RS256, and non-OpenAI protocol adapters.
