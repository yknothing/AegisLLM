# AegisLLM Architecture Refactor Progress

## Objective

Refactor until the architecture is coherent and evidence-backed. After each significant step: live-test, run autoreview, and commit.

## Baseline

- Branch: `codex/aegis-architecture-refactor`
- Starting HEAD: `4864cb8 feat: implement hybrid key source resolution (ADR-003)`
- Current state: architecture/runtime framework changes are present but uncommitted.
- Known blocker from prior verification: no `go` or `gofmt` on `PATH`; must establish a Go toolchain before claiming test evidence.

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
