# AegisLLM Release Refactor Progress

## Objective

Prepare AegisLLM for an excellent `v0.2.0` release candidate through review,
optimization, hardening, and behavior-preserving refactoring.

After each significant step:

1. live-test the system,
2. run autoreview,
3. commit a clean batch.

## Baseline

- Branch: `codex/aegis-architecture-refactor`
- Starting HEAD: `4864cb8 feat: implement hybrid key source resolution (ADR-003)`
- Current state: architecture/runtime framework changes are committed on `codex/aegis-architecture-refactor`.
- Release candidate version: `v0.2.0`.
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

## Prior Architecture Slice Completion Audit

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

## Step 4 - Runtime Truth Surface and Docker Contract

- Commit: `8a279e0 Align docs and defaults with runtime truth`.
- Versioning: `README.md`, `ARCHITECTURE.md`, and `REVIEW.md` identify `v0.2.0` as the remediated baseline superseding `v0.1.0`.
- Runtime guardrails:
  - `quota.enabled=true` fails fast until quota enforcement exists.
  - Redis rate limiter backend fails fast until implemented.
  - Vault KMS mode fails fast until implemented.
  - Non-zero provider/JWT/config TPM and budget claims fail closed until enforcement exists.
- Docker contract:
  - Image carries non-secret `/etc/aegis/aegis.json`.
  - Local encrypted key store path is `/var/lib/aegis/keys`.
  - Runtime user remains `nonroot:nonroot`.
  - Build now uses Docker target platform args so the binary architecture matches the image architecture.
- Mac mini live-test on `ceo`:
  - Host: `Mac-mini.local`, `arm64`.
  - Docker server: `29.1.3`, engine `linux/aarch64`.
  - `docker build --no-cache --pull ... -t aegis:codex-docker-test .` passed.
  - Build output confirmed `GOARCH=arm64`.
  - Image inspect confirmed `os=linux arch=arm64 user=nonroot:nonroot`.
  - Copied `/aegis` from the image and verified `ELF 64-bit ... ARM aarch64`.
  - Container ran with `--read-only`, env secrets, `/var/lib/aegis` volume, and returned `/health` = `{"status":"ok"}`.
  - `docker run --rm aegis:codex-docker-test --version` returned `aegis v0.2.0-docker-test`.
- Cleanup: remote test container, volume, image tag, and `/tmp/aegis-docker-test.NsccIM` were removed.

## Release Readiness Continuation - 2026-06-20

- Starting point:
  - Branch: `codex/aegis-architecture-refactor`.
  - Starting HEAD: `8a279e0 Align docs and defaults with runtime truth`.
  - Worktree: clean at continuation start.
- Current release claim is **not complete**. The next gates are:
  - Fresh local verification: `go test ./...`, `go vet ./...`, `go test -race ./...`, `govulncheck`.
  - Fresh live-test: local process smoke and Mac mini Docker smoke after any material change.
  - Autoreview: release-boundary review focused on security, unsupported capability fail-closed behavior, Docker contract, and documentation truth surface.
  - Commit each clean, significant batch.

### Step 5 - Release Hardening and Fail-Closed Cleanup

- Release artifacts:
  - Added `CHANGELOG.md` for `v0.2.0 - Release Candidate`.
  - Added `.dockerignore` so VCS metadata, local configs, key stores, databases, test output, and `tmp/` do not enter Docker build context.
  - Updated README to link the changelog.
- Runtime truth/fail-closed fixes:
  - Provider-level `max_rpm` is now explicitly reserved and non-zero values fail config/runtime validation until provider RPM enforcement exists.
  - Negative rate-limit and provider throttle values fail validation.
  - JWT validation now rejects missing/empty model permissions, and router model checks fail closed for empty permission lists.
  - Proxy egress now requires HTTPS, strips forwarded/sensitive hop headers, and propagates response streaming errors.
  - Proxy terminal middleware now treats any upstream/proxy error as a `502` accounting failure; if a response was already partially written, it avoids appending a second error body.
  - Provider API key material is removed from the upstream request and `SecureBytes` is closed as soon as the HTTP transport returns response headers, rather than after a streaming body completes.
  - Runtime middleware order is now represented by a private, tested plan used by production registration.
  - Removed the unused unsafe `MemZeroString` API.
  - Removed the unused Redis limiter stub; Redis remains a fail-fast unsupported backend.
  - File KMS backend resolves and confines paths under the configured key-store directory.
  - Reserved Vault/Admin/adapter implementation points no longer include misleading placeholder TODOs or key IDs in reserved errors.
- Reproducible verification tooling:
  - Makefile now supports `GO ?= go`.
  - `golangci-lint`, `govulncheck`, and `gosec` run through pinned `go run` versions.
- CI:
  - Added `.github/workflows/ci.yml`.
  - Workflow uses `permissions: contents: read`.
  - Official GitHub Actions are pinned to commit SHA:
    - `actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955` (`v4.3.0`).
    - `actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff` (`v5.6.0`).
  - Jobs cover Go `1.22.4` compatibility, Go `1.26.4` quality gates, and Docker read-only smoke testing.
  - Docker CI smoke asserts image OS, user, entrypoint, command, read-only root filesystem, and unauthenticated `401`.
- Local verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go vet ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race ./...` passed.
  - `make lint GO=$HOME/.cache/codex-go/go1.26.4/bin/go` passed with `0 issues`.
  - `make security GO=$HOME/.cache/codex-go/go1.26.4/bin/go` passed; `govulncheck` reported `No vulnerabilities found`.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml` passed.
  - `git diff --check` passed.
  - Local live-test verified `/health` = `{"status":"ok"}`, unauthenticated `/v1/chat/completions` = `401`, JWT missing `models` = `401`, valid JWT with no seeded provider key = `503`.
  - Added tests for runtime middleware registration order with and without rate limit.
  - Added server pipeline tests for onion execution order, abort short-circuiting, and provider API key zeroing/release after request completion.
  - Added middleware proxy tests for before-response upstream failures and partial-response streaming failures.
  - Added JWT negative limit-claim tests and KMS file backend keyID confinement tests.
  - Added header-stripping assertions for `X-Forwarded-Host` and `X-Forwarded-Proto`.
  - `make -n docker VERSION=v0.2.0 COMMIT=test BUILD_DATE=2026-06-20T00:00:00Z` confirmed `BUILD_DATE` override is honored.
- Autoreview:
  - Architecture/security reviewer flagged dirty verification state, unenforced provider `max_rpm`, empty-model fail-open behavior, sensitive forwarded headers, negative rate-limit validation, non-HTTPS egress, and missing pipeline-order tests.
  - Release/Docker reviewer flagged missing `.dockerignore`, dirty verification state, unpinned verification tools, Docker base digest review, CI/changelog gap, and adapter placeholder wording.
  - Follow-up reviewer flagged proxy `result + err` swallowing, Dockerfile comment drift, incomplete Makefile `.PHONY`, `BUILD_DATE` override drift, and weak CI Docker assertions.
  - Fixed the local blocking/should-fix items above. Remote GitHub CI green remains a tag/release gate after this batch is pushed.
- Mac mini Docker live-test on `ssh ceo`:
  - Host: `Mac-mini.local`, user `th`, `arm64`, macOS `26.3.1`.
  - Docker client/server: `29.1.3`, engine architecture `aarch64`.
  - BuildKit loaded `.dockerignore`; final build context was `227.38kB`.
  - `docker build --progress=plain --no-cache --pull ... -t aegis:codex-docker-test .` passed.
  - Build output confirmed `GOARCH=arm64`.
  - Image inspect confirmed `image=sha256:d669cd41d5a226a27d7c62e9f4d86ebbec691e1392b24acbe9f44fa129ec6afe os=linux arch=arm64 user=nonroot:nonroot entrypoint=["/aegis"] cmd=["--config","/etc/aegis/aegis.json"]`.
  - Docker assertions verified `os=linux`, `arch=arm64`, `user=nonroot:nonroot`, `entrypoint=["/aegis"]`, and `cmd=["--config","/etc/aegis/aegis.json"]`.
  - Copied `/aegis` from the image and verified `ELF 64-bit ... ARM aarch64`.
  - `docker run --rm aegis:codex-docker-test --version` returned `aegis v0.2.0-docker-test (commit: workspace, built: 2026-06-20T00:00:00Z)`.
  - Container ran with `--read-only`, env secrets, and `/var/lib/aegis` volume; `/health` returned `{"status":"ok"}` and unauthenticated `/v1/chat/completions` returned `401`.
  - Inspect/assertions confirmed `readonly=true user=nonroot:nonroot mounts=/var/lib/aegis:volume`.
  - Remote container, volume, image tag, copied binary, and `/tmp/aegis-docker-test.TOJjTJ` were removed.
- Clean HEAD verification after the release hardening commit:
  - `git status --short --branch` reported clean worktree, branch ahead 1.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go vet ./...` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race ./...` passed.
  - `make lint GO=$HOME/.cache/codex-go/go1.26.4/bin/go` passed with `0 issues`.
  - `make security GO=$HOME/.cache/codex-go/go1.26.4/bin/go` passed; `govulncheck` reported `No vulnerabilities found`.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml` passed.
  - `git diff --check` passed.
  - Clean HEAD local live-test verified `/health` = `{"status":"ok"}`, unauthenticated `/v1/chat/completions` = `401`, JWT missing `models` = `401`, valid JWT with no seeded provider key = `503`, and key-store directory mode = `700`.
- Remaining gates before release-complete claim:
  - Push the branch and verify GitHub CI green on the remote runner.
  - Tag `v0.2.0` only after remote CI is green and release artifacts are confirmed clean.

### Step 6 - Remote CI Gate Diagnosis

- Push status:
  - Local branch: `codex/aegis-architecture-refactor`.
  - Local HEAD: `b50f32a refactor: harden v0.2.0 release gates`.
  - Remote branch remained at `8a279e0 Align docs and defaults with runtime truth`.
  - `git push origin codex/aegis-architecture-refactor` was interrupted after no output for several minutes.
  - `GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false git push origin codex/aegis-architecture-refactor` also hung until interrupted.
  - Process inspection showed the push blocked under `git credential-osxkeychain get`.
  - Direct `printf 'protocol=https\nhost=github.com\n\n' | git credential-osxkeychain get` also hung until interrupted.
  - Disabling the helper with `git -c credential.helper= -c core.askPass=/usr/bin/false push origin codex/aegis-architecture-refactor` made the failure explicit: `fatal: could not read Username for 'https://github.com': Device not configured`.
  - `gh` is not installed.
  - `ssh -o BatchMode=yes -T git@github.com` returned `Permission denied (publickey)`.
- GitHub connector assessment with currently exposed connector tools:
  - The connector can read status/files and update refs to commits that already exist in GitHub.
  - It cannot upload the local `b50f32a` git commit object directly.
  - Replaying the 29-file diff through the contents API would create a different sequence of commits and diverge from the clean local batch, so it was not used.
- Go 1.22 Linux/amd64 compatibility smoke evidence:
  - On `ssh ceo`, ran a Linux/amd64 Go 1.22 container using the pinned builder image digest:
    - `golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052`
    - Container reported `go version go1.22.12 linux/amd64`.
    - `go test ./...` passed.
    - `go vet ./...` passed with no output and exit 0.
  - Remote temp directory `/tmp/aegis-go122-ci.h3S1Ii` was removed.
- Documentation truth-surface fix:
  - `docs/app-integration-strategy.md` now distinguishes virtual-key `rpm` claims from reserved provider-level `max_rpm`.
- Remaining gates before release-complete claim:
  - Fix local GitHub push credential path or provide another approved push route.
  - Push branch and verify GitHub Actions CI green on the remote runner.
  - Tag `v0.2.0` only after remote CI is green and release artifacts are confirmed clean.

### Step 7 - Release Policy Truth Surface

- Security policy fix:
  - `SECURITY.md` no longer claims a generic "Latest release" is supported.
  - It now states that no stable version is supported yet.
  - `v0.2.0` is recorded as a release candidate that is not supported until the release branch is pushed, GitHub Actions are green, and the `v0.2.0` tag exists.
- README Docker example:
  - Replaced `aegis:latest` with explicit local smoke tag `aegis:v0.2.0-rc-local`.
  - Added `make docker VERSION=v0.2.0-rc-local` before the run command so the example does not imply a stable latest release exists.
- Docker tag policy:
  - `make docker` now tags only the explicit `VERSION` by default.
  - `aegis:latest` is produced only when `DOCKER_TAG_LATEST=true` is set for a supported release.
- Documentation consistency:
  - Verified `internal/utils/logger.go` and `SensitiveFields` exist before keeping the secure logging guidance.
- Remaining gates before release-complete claim:
  - Push branch and verify GitHub Actions CI green on the remote runner.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 9 - Release Boundary Hardening

- Security-boundary fixes from the architecture expert review:
  - Panic recovery now logs only `panic_type` and never logs the panic value, because panic values can contain request content or secrets.
  - Added a regression test proving panic recovery does not log a secret panic string, request body content, or the `Authorization` header value.
  - Rate-limit unavailable responses now use structured `json.Marshal` output and return a generic `rate limit service unavailable` message instead of reflecting unsupported backend internals to clients.
  - Added a pipeline-level regression test proving the actual HTTP response body for an unsupported rate-limit backend is valid generic JSON and does not leak backend details.
  - Adapter middleware now fails closed when a provider ID has no provider-type mapping instead of silently defaulting to the OpenAI passthrough adapter.
  - Added adapter tests for missing provider-type mapping and known OpenAI mapping.
- Release/CI gate fixes from the release expert review:
  - GitHub Actions quality job now uses `make release-preflight GO=go VERSION=ci`, aligning remote CI with the local release gate script.
  - GitHub Actions Docker smoke now captures `/health` and asserts the response body equals `{"status":"ok"}`.
  - README Docker example now includes `--read-only` so the documented runtime path matches the CI and Mac mini smoke contract.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/server ./internal/middleware` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=b28cfb8-dirty BUILD_DATE=2026-06-20T00:00:00Z PORT=18088` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `238.32kB`.
    - Image `sha256:599eac4601fbca4c33e55560c76af21158571e49f54397a0ef7ce31111ad7641`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: b28cfb8-dirty, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
  - `git diff --check` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml` passed.
- Autoreview:
  - Security architecture reviewer confirmed the three reported should-fix findings were remediated and found no blocking security findings.
  - Release/operations reviewer confirmed CI health assertion, release-preflight reuse, and README read-only contract were remediated and found no new should-fix findings.
- Remaining gates before release-complete claim:
  - Commit this batch.
  - Push branch and verify GitHub Actions CI green on the final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 8 - Reproducible Release Gate Scripts

- Added `scripts/release_preflight.sh`:
  - Requires a clean worktree by default; `ALLOW_DIRTY=1` can be used while developing the script itself.
  - Runs `go test ./...`, `go vet ./...`, `go test -race ./...`, `make lint`, `make security`, `actionlint`, and `git diff --check`.
  - Verifies default Docker tags do not include `aegis:latest`.
  - Verifies `DOCKER_TAG_LATEST=true` explicitly adds `aegis:latest`.
- Added `scripts/ceo_docker_smoke.sh`:
  - Requires a clean worktree by default; `ALLOW_DIRTY=1` can be used while developing the script itself.
  - Syncs the current source tree to `ssh ceo`.
  - Uses `.dockerignore` as the rsync exclusion source so local secrets/config outside Docker build context are not copied to the remote temp directory.
  - Validates configurable remote/Docker/version fields against a conservative character allowlist before invoking SSH.
  - Uses run-id-suffixed image/container/volume defaults to reduce collision between runs.
  - Supports configurable `PORT` and uses run-id-suffixed temporary files for copied binaries and unauth response bodies.
  - Builds the Docker image with no cache and pulled bases.
  - Asserts image OS/architecture/user/entrypoint/cmd.
  - Copies `/aegis` from the image and verifies the binary with `file`.
  - Runs the container with `--read-only`, env secrets, and `/var/lib/aegis` volume.
  - Verifies `/health` returns `{"status":"ok"}` and unauthenticated `/v1/chat/completions` returns `401`.
  - Cleans remote created container IDs, named runtime container, volume, image, binary copy, unauth body, and temp source directory.
- Added Makefile targets:
  - `release-preflight`
  - `ceo-docker-smoke`
- Verification:
  - `sh -n scripts/release_preflight.sh` passed.
  - `sh -n scripts/ceo_docker_smoke.sh` passed.
  - `make -n release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` produced the expected command.
  - `make -n ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=workspace BUILD_DATE=2026-06-20T00:00:00Z` produced the expected command.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=workspace BUILD_DATE=2026-06-20T00:00:00Z PORT=18088` passed on `ssh ceo` after the script hardening changes.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `234.41kB`.
    - Image `sha256:4537de6f6dea345698aaeb35808b7daa99abb1c7cda75147bd5d35690031cda1`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Image tag `aegis:codex-docker-test-20260619175547-44607`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: workspace, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Remaining gates before release-complete claim:
  - Push branch and verify GitHub Actions CI green on the remote runner.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.
