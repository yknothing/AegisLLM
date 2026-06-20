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

### Step 4 - Runtime Truth Surface and Docker Contract

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

### Step 9 - Release Boundary Hardening

- Commit: `5554235 refactor: harden release boundary gates`.
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
  - `make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed on clean HEAD `5554235`.
  - `make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=5554235 BUILD_DATE=2026-06-20T00:00:00Z PORT=18088` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `238.89kB`.
    - Image `sha256:652c510786fe5c3e452bd732f362f85140fa6e63660c07d330775862a1394a55`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 5554235, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
  - `git diff --check` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml` passed.
- Autoreview:
  - Security architecture reviewer confirmed the three reported should-fix findings were remediated and found no blocking security findings.
  - Release/operations reviewer confirmed CI health assertion, release-preflight reuse, and README read-only contract were remediated and found no new should-fix findings.
- Remaining gates before release-complete claim:
  - Push branch and verify GitHub Actions CI green on the final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 10 - Remote Release Gate Recheck

- Documentation hygiene:
  - Reordered this progress log so Step 8 precedes Step 9.
  - Normalized Step 4 to the same heading level as the other step logs.
  - Updated Step 9 evidence from dirty-state smoke output to clean HEAD `5554235` output.
- Remote release gate status:
  - Local branch remains clean and ahead of `origin/codex/aegis-architecture-refactor` by 5 commits.
  - Local HEAD: `5554235dc853116b2423d621c10396a359b64ec1`.
  - Remote branch still points at `8a279e0547a6fb770b8f15620f26dbf37b5ea024`.
  - Local HTTPS push dry-run with credential helper disabled still fails with `fatal: could not read Username for 'https://github.com': Device not configured`.
  - `ssh ceo` has `gh`, but `gh auth status -h github.com` reports the active token for `bruceaiatgit` is invalid.
  - `ssh ceo` to `git@github.com` still returns `Permission denied (publickey)`.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 20 - Reserved Runtime Config Truth-Surface Tightening

- Architecture finding:
  - The old `v0.1.0` scaffold-style example and defaults exposed `quota.backend`, `quota.dsn`, `quota.default_budget`, and `store.*` values that looked like active SQLite persistence.
  - The same example still exposed inert `rate_limit.redis_url` and `kms.vault` fields even though Redis and Vault are planned/fail-fast capabilities.
  - The current runtime does not enforce quota and does not wire a control-plane store, so accepting those fields could make operators believe cost-control persistence exists.
- Fix:
  - Removed reserved Redis, Vault, quota, and store defaults from `aegis.example.json`; removed reserved quota/store defaults from `defaultConfig`.
  - Rejected present `rate_limit.redis_url`, `kms.vault`, `quota.backend`, `quota.dsn`, `quota.default_budget`, and `store` fields in JSON config validation.
  - Mirrored non-zero reserved field guardrails in `internal/runtime` so direct programmatic config construction cannot bypass `config.Load`.
  - Updated README, architecture truth surface, architecture design notes, threat-model residual risks, and changelog to describe the `v0.2.0` fail-fast behavior.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/config ./internal/runtime` passed.
  - `rg` confirmed `aegis.example.json`, Dockerfile, README, architecture docs, and threat-model no longer expose Redis URL, Vault config, quota SQLite backend/DSN/default budget, or store defaults; remaining matches are fail-fast code, reserved docs, and regression tests.
  - `git diff --check` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=da8a793-reserved-config-presence BUILD_DATE=2026-06-20T00:00:00Z PORT=18095` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `278.33kB`.
    - Image `sha256:e80ee597e06d950f7798ae3aeeddecd88b536d4b21045b7e212c0aa6d05d86d3`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: da8a793-reserved-config-presence, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture expert A found no bypass for reserved quota/store values through `config.Load` or `runtime.NewServer`, identified the stricter presence-based JSON config requirement that is now implemented, and confirmed no blocking findings after final recheck; the remaining wording drift was resolved by replacing `Non-empty` contract text with configured/presence wording.
  - Architecture expert B found no quota/store/BYOK current-runtime misstatement and identified remaining Redis/Vault inert fields in `aegis.example.json`, which are now removed and covered by fail-fast validation.
  - Architecture expert B final recheck found no blocking or should-fix findings and independently verified `./internal/config ./internal/runtime`, `./...`, `git diff --check`, and a `ceo` Docker smoke with `health={"status":"ok"}`, unauthenticated `401`, read-only runtime, and `nonroot:nonroot`.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 11 - Release Plan and Go/No-Go Runbook

- Added `docs/release-plan-v0.2.0.md` as the public release-management artifact for `v0.2.0`.
- The release plan records the current decision as **No-Go for a supported release** until:
  - local release preflight passes,
  - `ceo` Docker smoke passes,
  - the branch is pushed without rewriting the clean local commit sequence,
  - GitHub Actions is green for the exact commit to tag,
  - release owner, verifier, and approver are assigned by name,
  - `v0.2.0` tag is created only after the above gates.
- The plan explicitly lists included scope and excluded capabilities: Admin issuance/revocation, Vault, Redis, quota/budget/TPM enforcement, RS256/JWKS, and Anthropic/Gemini adapters remain out of the supported release scope.
- Added rollback/abort guidance:
  - before tag, rollback means do not release and keep `v0.2.0` unsupported;
  - if a tag is accidentally created before gates pass, delete the remote tag and publish a correction;
  - after tag, fixes must land as a new patch release candidate instead of rewriting release history.
- Linked the release plan from `docs/README.md`, `README.md`, and `SECURITY.md`.
- Remote release gate recheck at step start:
  - Local branch was clean and ahead of `origin/codex/aegis-architecture-refactor` by 6 commits.
  - Local HEAD was `40768df5c889167d8f17fb10be7cb213c25b3388`.
  - Remote branch still pointed at `8a279e0547a6fb770b8f15620f26dbf37b5ea024`.
- Verification:
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=40768df-release-plan BUILD_DATE=2026-06-20T00:00:00Z PORT=18088` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `243.44kB`.
    - Image `sha256:98e984ea7595f44cde7a38d26199dce6f2c301142835065097153833a92c6934`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 40768df-release-plan, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Release-boundary self-review found no blocking findings.
  - Fixed review precision issues before commit: changed ambiguous `Go criteria` wording to `go/no-go criteria` and made owner, verifier, and approver naming requirements consistent.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 12 - Recursive Audit Log Redaction

- Security finding:
  - `internal/utils.SafeHandler` redacted only top-level field names.
  - Sensitive values nested inside `slog.Group`, `WithAttrs`, or a resolved `slog.LogValuer` group could bypass the defense-in-depth audit logger and be emitted by the wrapped JSON handler.
- Fix:
  - Added normalized sensitive-key matching for common secret/content variants such as `X-Api-Key`, `client_secret`, `private_key`, `messages`, `prompt`, `completion`, and `body`.
  - Added recursive `sanitizeAttr` handling for nested `slog.Group` values.
  - Resolved `slog.LogValuer` values before group recursion so deferred groups are redacted before the wrapped handler outputs them.
  - Preserved exact structural token-count metadata fields such as `prompt_tokens`, `completion_tokens`, and `total_tokens` to keep the `SECURITY.md` audit-log contract usable for cost/usage metadata without allowing prompt or completion bodies.
  - Added regression coverage in `internal/utils/logger_test.go` for top-level redaction, safe structural token counts, nested group redaction, `WithAttrs`, and resolved `LogValuer` groups.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/utils` passed.
  - `git diff --check` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=bb051b8-logger-redaction BUILD_DATE=2026-06-20T00:00:00Z PORT=18088` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `248.67kB`.
    - Image `sha256:5171d1c8da75192abd4ed12a65332cb5f885205a14159f9e2114f502b8f2d230`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: bb051b8-logger-redaction, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Security review found the original top-level-only redaction was too narrow for nested `slog` structures.
  - Review also found the initial fragment-based redaction would have over-redacted allowed structural token-count metadata, contradicting the `SECURITY.md` audit-log contract; the exact token-count allowlist was added before commit.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 13 - Proxy Header and Upstream TLS Hardening

- Security finding:
  - Upstream request header forwarding was still blacklist-based, so unlisted ingress, tenant, trace, or provider-account headers could be reflected to external providers.
  - Non-streaming upstream response headers were copied directly to clients, allowing provider `Set-Cookie`, hop-by-hop, or proxy-authentication headers to cross the gateway boundary.
  - `internal/proxy` documented TLS 1.3 minimum for outbound connections, but the transport did not explicitly set `TLSClientConfig.MinVersion`.
- Fix:
  - Changed upstream request header forwarding to a minimal allowlist: `Accept`, `Content-Type`, and `User-Agent`.
  - Added response-header filtering for `Set-Cookie`, hop-by-hop headers, and proxy-authentication headers.
  - Set upstream `http.Transport` TLS minimum to `tls.VersionTLS13`.
  - Added proxy tests for TLS 1.3 transport configuration, request header allowlist behavior, and unsafe upstream response header stripping.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/proxy` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=9a99d08-proxy-header-tls BUILD_DATE=2026-06-20T00:00:00Z PORT=18088` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `252.49kB`.
    - Image `sha256:4f097811ca007b4ba1cc631f36cf786d4368d839e2fafc841dbffd6efdaeeac2`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 9a99d08-proxy-header-tls, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Security architecture reviewer found the request-header blacklist and missing TLS 1.3 enforcement should be fixed before a public gateway release; both were remediated in this step.
  - Release/operations reviewer found the dirty-tree state and missing progress record were release blockers for the current candidate; this step records the change before commit and clean-HEAD verification.
  - Security architecture reviewer also found two remaining Auth/JWT blocking issues: weak HS256 signing-key acceptance and unused `auth.token_expiry` maximum TTL. These remain release-blocking and will be repaired in the next implementation batch.
- Remaining gates before release-complete claim:
  - Fix the remaining Auth/JWT release blockers.
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 14 - Auth/JWT Release-Blocking Hardening

- Security finding:
  - HS256 JWT signing keys only needed to be non-empty, so weak `AEGIS_JWT_KEY` values could start the gateway and validate attacker-forged virtual keys if brute-forced.
  - `auth.token_expiry` was loaded and passed through config but was not enforced against JWT `exp - iat`, allowing arbitrarily long-lived tokens as long as `exp` was in the future.
  - Auth 401 responses exposed distinct client-facing failure categories such as missing header, invalid format, or revoked token, despite the auth middleware comment requiring generic failures.
- Fix:
  - Added `middleware.MinJWTSigningKeyBytes` and reject HS256 signing keys shorter than 32 bytes in both token validation and runtime env loading.
  - Reject non-positive `auth.token_expiry` in config and runtime validation.
  - Enforce max token lifetime: when `auth.token_expiry` is configured, `iat` must exist, `exp` must be after `iat`, and `exp - iat` must not exceed the configured maximum.
  - Unified auth failure responses to `invalid or expired virtual key`.
  - Updated `SECURITY.md` and `CHANGELOG.md` for the stronger virtual-key signing contract.
  - Added regression coverage for weak signing keys, long-lived JWT rejection, missing `iat`, non-positive `auth.token_expiry`, runtime JWT key loading, and generic auth failure JSON.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/middleware ./internal/runtime ./internal/config` passed.
  - Initial `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` failed on `staticcheck` for an unnecessary nil check in a test cleanup.
  - Removed the unnecessary nil check.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed after the fix.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=fc8aed1-auth-jwt-final BUILD_DATE=2026-06-20T00:00:00Z PORT=18088` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `258.78kB`.
    - Image `sha256:c6ded14562e83187f3a3c879e556e113f63fc351cfaaa9ef36443e32521d3ca1`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: fc8aed1-auth-jwt-final, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Security architecture reviewer identified weak HS256 signing-key acceptance and unused `auth.token_expiry` as release-blocking. Both are now enforced with regression tests.
  - Auth error category disclosure was identified as a should-fix oracle risk and is now generic at the client boundary.
- Remaining gates before release-complete claim:
  - Re-run clean-HEAD release preflight and `ceo` Docker smoke after commit.
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 15 - Adapter Target Path Boundary Hardening

- Security finding:
  - `internal/middleware.buildTargetURL` rejected absolute URLs but still allowed network-path references such as `//evil.example/v1/chat/completions`.
  - The proxy engine egress allowlist would still block non-allowlisted hosts, but the middleware/plugin boundary should not let adapter-generated paths override the configured provider authority and rely on a later defense to catch it.
- Fix:
  - Restricted provider target paths to root-relative paths.
  - Rejected adapter-generated target paths that include a scheme, host, or userinfo.
  - Added regression tests for accepted root-relative paths, rejected network-path references, and rejected relative paths without a leading slash.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/middleware` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=52e1a67-target-path-hardening BUILD_DATE=2026-06-20T00:00:00Z PORT=18089` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `259.99kB`.
    - Image `sha256:66da3ca3a9ab98c9b8d16178aa4dd2fb2ed46ef90b00ade4b41870993ada8bb2`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 52e1a67-target-path-hardening, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture expert review identified the original `buildTargetURL` authority-override behavior as the current blocking release issue and recommended the same root-relative path fix.
  - Security expert review independently identified the same provider-key-to-wrong-authority risk and confirmed the current patch is the right first fix.
  - Self-review confirmed the fix closes the authority-override edge before proxy egress validation while preserving the existing proxy allowlist as a second defense.
  - Scope check confirmed built-in adapters already return root-relative `/v1/chat/completions` paths, so the change does not alter supported OpenAI-compatible request routing.
  - Security expert review also found a remaining release blocker: `key_source=byok` trusts JWT `byok_key_id` without service-side owner/provider binding. This will be handled in the next clean batch.
- Remaining gates before release-complete claim:
  - Fix or explicitly fail closed the BYOK runtime path before `v0.2.0` release.
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 16 - BYOK Runtime Fail-Closed Boundary

- Security finding:
  - `key_source="byok"` trusted the JWT-provided `byok_key_id` directly in KMS key resolution.
  - Without server-side owner/provider binding, a valid BYOK token could route a user-owned provider key to the wrong allowlisted provider.
- Fix:
  - Changed auth validation so the `v0.2.0` runtime accepts only pool key-source tokens.
  - Rejected `key_source="byok"` and rejected pool tokens that carry `byok_key_id`.
  - Added KMS defense-in-depth so any non-pool key source resolves to no key before KMS lookup.
  - Removed the reserved BYOK template from default subscription templates.
  - Updated README, architecture docs, ADRs, app integration notes, release plan, review notes, changelog, and package comments so BYOK is consistently described as future/reserved until owner/provider binding exists.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/middleware ./internal/server ./internal/subscription ./internal/admin` passed.
  - `rg` found no remaining text claiming current runtime BYOK support; remaining hits describe `future`, `reserved`, `planned`, or fail-closed behavior.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=3506120-byok-fail-closed BUILD_DATE=2026-06-20T00:00:00Z PORT=18090` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `263.75kB`.
    - Image `sha256:07350b7e4621155f9e358827d463d55854a2b810d08b39eab282681ae94cb21a`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 3506120-byok-fail-closed, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Attempted two final read-only architecture/security expert reviews for this dirty patch, but both subagents failed with usage-limit errors before producing evidence, so they are not counted as validation.
  - Mainline security self-review traced auth -> router -> KMS -> proxy and confirmed `key_source="byok"` now fails during token validation and KMS no longer trusts `ctx.BYOKKeyID` for non-pool sources.
  - Mainline architecture self-review searched for stale BYOK-current-runtime claims and found remaining hits describe BYOK as `future`, `reserved`, `planned`, or fail-closed.
  - Scope check confirmed pool key-source tokens still resolve through provider-to-pool KMS mapping, while reserved BYOK templates are no longer emitted by default subscription templates.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 17 - Reserved Rate-Limit Config Guardrail Tightening

- Architecture finding:
  - Documentation and release notes said Redis and non-zero TPM rate-limit controls fail fast.
  - Config/runtime validation only rejected those fields when `rate_limit.enabled=true`, so a disabled rate-limit block could still carry reserved or invalid settings without being rejected.
- Fix:
  - Moved `rate_limit.backend`, `default_rpm`, `default_tpm`, and `default_max_concurrency` validation outside the `enabled` gate in both config and runtime validation.
  - Kept middleware registration controlled by `rate_limit.enabled`; this change only tightens accepted configuration truth.
  - Added config/runtime tests for disabled Redis, disabled default TPM, disabled unknown backend, and disabled negative RPM.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/config ./internal/runtime` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=a93c72f-rate-limit-guardrail BUILD_DATE=2026-06-20T00:00:00Z PORT=18091` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `264.93kB`.
    - Image `sha256:fc8066d4930d302a8d5bec6e28e046670d70dfd3f985cec5457e263cf4df0ca2`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: a93c72f-rate-limit-guardrail, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Self-review confirmed this closes the Redis-like mismatch where a reserved dependency could remain in accepted config merely because the feature was disabled.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 18 - Upstream Response Header Allowlist

- Security finding:
  - Non-streaming upstream response header forwarding used a blocklist.
  - Although known unsafe headers were stripped, unknown provider debug, tenant, CORS, auth-challenge, proxy, or account headers could still be reflected to clients.
- Fix:
  - Replaced response-header blocklist with an explicit allowlist.
  - Current client response contract allows content type, upstream request IDs, generic/rich rate-limit metadata, OpenAI processing/version metadata, and `Retry-After`.
  - Added regression coverage proving `Set-Cookie`, hop-by-hop, proxy auth, upstream auth challenge, CORS, debug, provider-account, internal-request, and upstream policy headers are stripped.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/proxy` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=0d64aa0-response-header-allowlist BUILD_DATE=2026-06-20T00:00:00Z PORT=18092` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `267.86kB`.
    - Image `sha256:98a0dc8cc210da50121cbb98309f6b91f346dcf19a2133a8b7455d3261e59e60`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 0d64aa0-response-header-allowlist, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Self-review confirmed response headers are now allowlisted and no `blockedResponseHeaders` path remains.
  - Scope check confirmed streaming responses still set their own SSE headers and non-streaming body forwarding remains streaming `io.Copy` without full buffering.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 19 - KMS Memory and Egress Truth-Surface Tightening

- Architecture/security finding:
  - Local KMS comments claimed a best-effort `mlock` attempt that the implementation does not perform.
  - `SECURITY.md` described memory zeroing and egress filtering with stronger guarantees than Go strings, crypto internals, and process/config compromise allow.
- Fix:
  - Removed the unsupported `mlock` claim.
  - Clarified that local KMS zeroes Store-owned master-key bytes, while Go AES/GCM internals may retain key schedule material that Aegis cannot explicitly zero.
  - Clarified that environment strings are not zeroed by local KMS loading.
  - Reworded memory-zeroing and egress-filtering security text to describe the actual runtime boundary.
  - Added matching residual risks to `docs/threat-model.md`.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/kms/local` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=3f44e49-kms-egress-truth-final BUILD_DATE=2026-06-20T00:00:00Z PORT=18093` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `268.75kB`.
    - Image `sha256:35804d7e6a04fac4fb1d41c973bc816197cd1076f19b27aa2672357ca3663ff3`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 3f44e49-kms-egress-truth-final, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Self-review confirmed the change is a truth-surface narrowing only; no runtime behavior changed.
  - Searched for remaining `mlock` and overbroad egress/memory claims and found the prior high-risk wording removed from the touched surfaces.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.
