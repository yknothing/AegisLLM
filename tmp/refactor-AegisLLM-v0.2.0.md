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

### Final Release Evidence - v0.2.0

- Final release commit:
  - short SHA: `aece329`;
  - full SHA: `aece3298720d210f5dd242aebd72ac71af4b2aff`;
  - commit message: `docs: finalize v0.2.0 release status`.
- Release ownership:
  - release owner: `yknothing`;
  - verification owner: Codex execution thread running local release gates, `ssh ceo` Docker smoke, and GitHub Actions status checks;
  - approver: `yknothing`.
- Local verification on the final release commit:
  - `make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `make local-smoke GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local COMMIT=aece329 PORT=18131` passed with `version=aegis v0.2.0-rc-local (commit: aece329, built: 2026-06-20T16:27:42Z)`, `health={"status":"ok"}`, and `unauth_status=401`.
- Mac mini Docker verification on `ssh ceo`:
  - `make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=aece329 BUILD_DATE=2026-06-20T16:27:42Z PORT=18132` passed.
  - host: `Mac-mini.local`;
  - Docker version: `29.1.3`;
  - Docker arch: `aarch64`;
  - image id: `sha256:1533bb17ac46b6bf4372fd66b1cf0a62e813703b3caa41b0820ce9ca5cea939f`;
  - version assertion output: `aegis v0.2.0-docker-test (commit: aece329, built: 2026-06-20T16:27:42Z)`;
  - `health={"status":"ok"}`;
  - `unauth_status=401`;
  - `readonly=true`;
  - `user=nonroot:nonroot`.
- Remote GitHub verification:
  - branch push succeeded: `codex/aegis-architecture-refactor` from `3420792` to `aece329`;
  - remote branch: `refs/heads/codex/aegis-architecture-refactor` points to `aece3298720d210f5dd242aebd72ac71af4b2aff`;
  - GitHub Actions run: `27877115839`;
  - run URL: `https://github.com/yknothing/AegisLLM/actions/runs/27877115839`;
  - run `headSha`: `aece3298720d210f5dd242aebd72ac71af4b2aff`;
  - conclusion: `success`;
  - jobs passed: `Go 1.22 compatibility`, `Quality gates`, and `Docker smoke`.
- Release tag:
  - local annotated tag object: `da28c521dc726ec603583f38ac9d9d8d18b1f79e`;
  - local peeled tag target: `aece3298720d210f5dd242aebd72ac71af4b2aff`;
  - remote annotated tag object: `da28c521dc726ec603583f38ac9d9d8d18b1f79e`;
  - remote peeled tag target: `aece3298720d210f5dd242aebd72ac71af4b2aff`.
- Known non-blocking CI annotations:
  - GitHub Actions reported Node.js 20 deprecation warnings for pinned official actions.
  - `actions/setup-go` cache restore warned that `go.sum` was absent; the workflow still completed successfully.
- Post-tag note:
  - This final evidence record is committed after the `v0.2.0` tag so the tag remains pointed at the verified release commit.

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

### Step 34 - Server Runtime Bound Validation

- Architecture/security finding:
  - `server.read_timeout`, `server.write_timeout`, `server.shutdown_timeout`, and `server.max_request_body_size` were documented as explicit runtime bounds but were not validated as positive values.
  - A non-positive body-size limit could fall back to middleware defaults, and a non-positive timeout could weaken the server/proxy runtime boundary instead of failing configuration early.
  - Security autoreview also found that `server.New` could bypass the runtime validation layer, and that `max_request_body_size` needed an explicit upper bound because body reads use `io.ReadAll(io.LimitReader(..., limit+1))`.
- Fix:
  - Added shared `config.ValidateServerConfig` validation for server read, write, shutdown, and max-body bounds.
  - Reused that validation from `internal/config`, `internal/runtime`, and `internal/server.New` so direct server construction cannot bypass the boundary.
  - Added an explicit 64 MiB `server.max_request_body_size` configuration ceiling and rejected larger limits before body reads.
  - Added middleware defense-in-depth so direct calls to `readAndReplaceBody` reject configured limits above the shared maximum before evaluating `limit+1`.
  - Added config/runtime/server/middleware regression coverage for zero, negative, and oversized server bounds.
  - Updated `CHANGELOG.md`, `SECURITY.md`, and `docs/threat-model.md`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/config ./internal/runtime` passed before the autoreview follow-up fix.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed before the autoreview follow-up fix.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=9df2e39-server-bound-validation BUILD_DATE=2026-06-20T00:00:00Z PORT=18119` passed on `ssh ceo` before the autoreview follow-up fix.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/config ./internal/runtime ./internal/server ./internal/middleware` passed after the autoreview follow-up fix.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed after the autoreview follow-up fix, including package tests, race tests, `golangci-lint`, `govulncheck`, and `gosec`.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=9df2e39-server-bound-validation BUILD_DATE=2026-06-20T00:00:00Z PORT=18120` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `330.32kB`.
    - Image `sha256:35e69a2276644f34371abd4f7c6d4f96329149b654e30e42857da2aff4c6d7cb`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 9df2e39-server-bound-validation, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
  - `git diff --check` and `gofmt -l` passed with no output.
- Autoreview:
  - Architecture/release-boundary reviewer found no blocking or should-fix issues in the initial positive-bound validation patch.
  - Security reviewer found two should-fix issues: `server.New` could still bypass server-bound validation, and `max_request_body_size` needed an upper bound plus overflow-safe body-read handling. Both are now addressed in this step.
  - Final architecture autoreview found no blocking, should-fix, or nit findings and confirmed both prior should-fix items are closed.
  - Final security audit found no blocking, should-fix, or nit findings and confirmed the body-limit overflow/oversized-configuration path is fail-closed before `limit+1`.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 35 - Release Evidence Gate Hardening

- Release engineering finding:
  - `ceo-docker-smoke` accepted arbitrary `COMMIT` strings, so Docker `--version` evidence was not bound to the current commit.
  - `release-preflight` used cacheable Go test invocations, which weakened fresh release evidence.
  - `CHANGELOG.md` required local process `/health` smoke, but there was no reusable `make local-smoke` gate.
- Fix:
  - Added `scripts/local_smoke.sh` and `make local-smoke` to build a temporary binary, run a temporary config/key-store, verify `--version` includes the expected commit marker, verify `/health`, and verify unauthenticated `/v1/chat/completions` returns `401`.
  - Changed `release-preflight` to run `go test -count=1 ./...`, `go test -race -count=1 ./...`, and the new local smoke gate.
  - Updated GitHub Actions Go 1.22 compatibility testing to use `go test -count=1 ./...`.
  - Tightened `ceo-docker-smoke` and `local-smoke` commit evidence:
    - clean worktree requires `COMMIT` to equal current `git rev-parse --short HEAD`;
    - dirty `ALLOW_DIRTY=1` smoke uses or requires `workspace-<HEAD>` prefix instead of arbitrary labels.
  - Added explicit Docker artifact version assertions:
    - `ceo-docker-smoke` now fails if `docker run --rm "$IMAGE" --version` does not include `commit: ${COMMIT}`;
    - CI Docker inspection now fails if the built image version does not include `commit: ${GITHUB_SHA}`.
  - Updated README, CHANGELOG, and release plan so local smoke has a reproducible command.
- Verification:
  - `sh -n scripts/local_smoke.sh scripts/release_preflight.sh scripts/ceo_docker_smoke.sh` passed.
  - `ALLOW_DIRTY=1 PORT=18121 make local-smoke GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed with `version=aegis v0.2.0-rc-local (commit: workspace-8ddde5f, built: 2026-06-20T15:06:07Z)`, `health={"status":"ok"}`, and `unauth_status=401`.
  - `ALLOW_DIRTY=1 COMMIT=workspace PORT=18122 GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local scripts/local_smoke.sh` failed fast as expected with `dirty local smoke COMMIT must start with workspace-8ddde5f`.
  - `ALLOW_DIRTY=1 COMMIT=workspace VERSION=v0.2.0-docker-test BUILD_DATE=2026-06-20T00:00:00Z PORT=18122 scripts/ceo_docker_smoke.sh` failed fast as expected with `dirty ceo docker smoke COMMIT must start with workspace-8ddde5f`.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed after the Docker artifact version assertion fix, including uncached package tests, uncached race tests, `golangci-lint`, `govulncheck`, `gosec`, actionlint, Docker tag checks, and local smoke output `version=aegis v0.2.0-rc-local (commit: workspace-8ddde5f, built: 2026-06-20T15:18:49Z)`, `health={"status":"ok"}`, `unauth_status=401`.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test BUILD_DATE=2026-06-20T00:00:00Z PORT=18127` passed on `ssh ceo` after the Docker artifact version assertion fix.
  - `ceo-docker-smoke` evidence:
    - host: `Mac-mini.local`;
    - Docker version: `29.1.3`;
    - Docker arch: `aarch64`;
    - image id: `sha256:ee2676562f7be87ddffa101843b65da939536d7a10d45c69aee0413528a7910f`;
    - version assertion output: `aegis v0.2.0-docker-test (commit: workspace-8ddde5f, built: 2026-06-20T00:00:00Z)`;
    - `health={"status":"ok"}`;
    - `unauth_status=401`;
    - `readonly_runtime=true`;
    - `user=nonroot:nonroot`.
- Expert review input:
  - Release/CI expert identified the three release evidence gate issues fixed in this step.
  - Architecture/security expert identified additional next candidates: provider ID uniqueness, strict unknown config fields, and local KMS existing-directory permissions. These are not part of this batch to keep the change bounded.
  - Final code-review and security-audit agents found one should-fix after the first implementation pass: Docker/CI had to assert image `--version` commit evidence rather than only print it. That should-fix was implemented and reverified by release preflight plus `ssh ceo` Docker smoke.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 33 - Bounded SSE Scanner Line Limit

- Architecture/reliability finding:
  - Streaming proxy used `bufio.Scanner` for SSE lines without setting an explicit buffer.
  - Go's default scanner token limit can reject provider stream events above 64 KiB, which is too implicit for the `v0.2.0` streaming proxy baseline.
- Fix:
  - Set an explicit bounded SSE scanner buffer: 64 KiB initial buffer and 1 MiB max line size.
  - Added regression coverage that forwards a single SSE `data:` line larger than Go's default scanner token size.
  - Added regression coverage that rejects an SSE `data:` line above the explicit max line size, keeping stream parsing bounded.
  - Updated `CHANGELOG.md`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/proxy` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race -count=10 -run 'TestStreamSSE' ./internal/proxy` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed, including package tests, race tests, `golangci-lint`, `govulncheck`, and `gosec`.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=0763f51-sse-line-buffer BUILD_DATE=2026-06-20T00:00:00Z PORT=18117` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `321.62kB`.
    - Image `sha256:b4522e0eff72cc76a41a4bf905db97c41cb1d81661d19b8d9f926b007f8bdc65`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 0763f51-sse-line-buffer, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Attempted architecture and security subagent autoreviews, but both failed with usage-limit errors before producing usable review evidence.
  - Mainline code-review/security-audit pass found no blocking or should-fix findings.
  - Mainline review confirmed the change is bounded, preserves streaming/token-counting behavior, and keeps oversized single-line events fail-closed.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 32 - Server TLS/mTLS Config Boundary Evidence

- Architecture finding:
  - README lists server TLS as implemented and says mTLS requires `ca_file`.
  - Runtime had the TLS/mTLS configuration path, but `internal/server` lacked focused tests proving the config boundary.
- Fix:
  - Added `internal/server/server_test.go`.
  - Covered TLS config without `ca_file`: TLS 1.3 minimum and no client-certificate requirement.
  - Covered TLS config with a generated test CA: TLS 1.3 minimum, populated client CA pool, and `RequireAndVerifyClientCert`.
  - Covered invalid CA PEM fail-closed behavior.
  - Runtime code was not changed.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/server` passed.
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -race -count=5 -run 'TestBuildTLSConfig' ./internal/server` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed, including package tests, race tests, `golangci-lint`, `govulncheck`, and `gosec`.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=e50d8c6-server-tls-tests BUILD_DATE=2026-06-20T00:00:00Z PORT=18116` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `319.72kB`.
    - Image `sha256:4464114b7c0951eb8d26c2a2d5591087919e5de8ab984d6033899ffebd4fb063`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: e50d8c6-server-tls-tests, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture reviewer found no blocking or should-fix issues and judged the tests sufficient for the current TLS/mTLS configuration-level claim.
  - Security reviewer found no release blocker and confirmed the generated CA does not write private keys to disk.
  - Scope boundary: this is server TLS/mTLS config-boundary evidence, not end-to-end TLS handshake coverage.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 31 - Per-Key Concurrency Claim and Ceiling Semantics

- Architecture/security finding:
  - `subscription.Template` exposed tier-level `MaxConcurrency`, but the runtime JWT schema did not have a `max_concurrency` claim and auth always set `ctx.MaxConcurrency = 0`.
  - This left a truth-surface gap: docs/templates implied per-tier concurrency while runtime only enforced the global default concurrency.
  - Initial autoreview also found two blocking concurrency risks after adding the claim:
    - `memoryLimiter` cached the first seen per-key concurrency max in the tracker, so later stricter limits for the same `kid` would not apply.
    - A large positive `max_concurrency` claim could bypass a stricter non-zero `default_max_concurrency`.
- Fix:
  - Added optional `max_concurrency` support to `VirtualKeyClaims`.
  - Auth now populates `ctx.MaxConcurrency` from the signed claim.
  - Negative `max_concurrency` claims fail closed.
  - RateLimiter now treats non-zero `default_max_concurrency` as a deployment-wide ceiling; signed per-key claims can tighten but cannot widen it.
  - `memoryLimiter` no longer caches the first seen concurrency max; it evaluates the current request limit each acquisition.
  - Added regression coverage for auth claim propagation, negative claim rejection, per-key context concurrency enforcement, sticky-tracker tightening, and default ceiling behavior.
  - Updated README, app integration notes, ADRs, subscription comments, and CHANGELOG to describe default/per-key concurrency and ceiling semantics.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/middleware ./internal/subscription` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed, including package tests, race tests, `golangci-lint`, `govulncheck`, and `gosec`.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=d1ed069-max-concurrency-ceiling BUILD_DATE=2026-06-20T00:00:00Z PORT=18115` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `316.31kB`.
    - Image `sha256:77a98a5c55b0d034e9bfd97347e2cc3e102047fe2929a266b9593fc92752b0e3`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: d1ed069-max-concurrency-ceiling, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - First architecture/security review found the sticky-tracker max and oversized-claim/default-ceiling problems; both were fixed before commit.
  - Follow-up architecture review found no blocking or should-fix issues and recommended submission.
  - Follow-up security review confirmed both prior blocking findings were closed, found no new blocking or should-fix issues, and recommended submission.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 30 - Rate-Limit Baseline Behavior Evidence

- Architecture finding:
  - `v0.2.0` docs and README claim an implemented in-memory request/concurrency rate-limiting baseline.
  - Existing tests covered reserved TPM fail-closed behavior and unsupported backend sanitization, but did not directly prove real `memoryLimiter` RPM overflow or default-concurrency overflow behavior.
- Fix:
  - Added `TestRateLimiterEnforcesRPMWithMemoryLimiter`.
  - Added `TestRateLimiterEnforcesDefaultConcurrencyWithMemoryLimiter`.
  - Both tests use the public `RateLimiter` constructor with the real `memory` backend and the same `VirtualKeyID`, proving the second request is rejected with `429` once RPM or concurrency is exhausted.
  - Runtime code was not changed.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/middleware` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed, including package tests, race tests, `golangci-lint`, `govulncheck`, and `gosec`.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=7073078-ratelimit-baseline-tests BUILD_DATE=2026-06-20T00:00:00Z PORT=18113` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `310.26kB`.
    - Image `sha256:0eeeeca76c63efa8030ad251c9131b5cf1c120c72c625b6430d72c2e6d1c3595`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 7073078-ratelimit-baseline-tests, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture expert found no blocking or should-fix issues and judged the new tests sufficient for the `in-memory request/concurrency rate limiting baseline implemented` release claim.
  - Security expert found no blocking or should-fix issues, no material race/deadlock/flaky risk, and recommended committing the batch.
  - Security expert also ran `$HOME/.cache/codex-go/go1.26.4/bin/go test -race -count=10 -run 'TestRateLimiterEnforces(RPM|DefaultConcurrency)WithMemoryLimiter' ./internal/middleware`, which passed.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 29 - Example Config Egress Truth Surface

- Architecture/security finding:
  - The example config and Docker default config still carried a disabled Anthropic provider placeholder and `api.anthropic.com` in the egress allowlist.
  - Runtime skipped the disabled provider, so this was not a release blocker, but it weakened the `v0.2.0` truth surface: the default allowlist included a non-current provider host while the release scope only supports `openai` and OpenAI-compatible `deepseek`.
- Fix:
  - Removed the disabled Anthropic provider placeholder from `aegis.example.json`.
  - Removed `api.anthropic.com` from the example/Docker default egress allowlist.
  - Added `TestExampleConfigEgressMatchesEnabledRuntimeProviders` so the example config must contain only enabled runtime-supported providers and its egress allowlist must exactly match those enabled provider hosts.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/runtime ./internal/config` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=6c20c45-example-egress-truth BUILD_DATE=2026-06-20T00:00:00Z PORT=18112` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `307.11kB`.
    - Image `sha256:dacbfc4c7c7fd22b117f12d7747ed088b7a41856f2505478fb27c298c925f621`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 6c20c45-example-egress-truth, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture expert Gibbs found no release blocker or should-fix, confirmed the diff aligns with README/release-plan provider scope, and confirmed the regression test constrains only the example/Docker default truth surface rather than custom configs.
  - Security expert Nash found no release blocker or should-fix, confirmed the Docker default allowlist is narrowed, and found no new leakage or fail-open surface.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 28 - Architecture Truth-Surface Follow-Up Cleanup

- Architecture/security finding:
  - After the Redis necessity review, two architecture experts checked for similar over-commitment patterns in the current `v0.2.0` truth surface.
  - No release blocker was found, but residual should-fix mismatches remained in integration examples, subscription templates, Router comments, Admin scaffold comments/routes, CLI godoc, Vault scaffold comments, dependency policy, and release evidence wording.
- Fix:
  - Changed app integration examples so current pool-mode JWTs only show OpenAI-compatible `openai`/`deepseek` model names.
  - Changed tier quota wording to `App-side or future Aegis quota` so `v0.2.0` does not imply plan/day quota enforcement.
  - Removed Claude/Gemini and wildcard model grants from default subscription templates until their adapters are enabled, and added a regression test.
  - Narrowed Router comments to same-model priority routing with weight as a deterministic tie-breaker; cross-model fallback and probabilistic weighted balancing remain unimplemented.
  - Required admin token auth for reserved `GET /admin/health`, removed the false "all admin operations are audit-logged" scaffold claim, and added route-level tests.
  - Reworded the CLI package comment so cost control is described as planned architecture, not current enforcement.
  - Clarified Vault scaffold comments so unimplemented methods are marked as reserved implementation points.
  - Clarified dependency policy: runtime/module dependencies are pinned by Go modules and committed in `go.sum` when present; release tools are pinned by explicit `go run module@version` entries and Go checksum verification.
  - Updated `REVIEW.md` and `CHANGELOG.md` so release evidence is represented as required gates before tag creation, not final completed evidence.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/admin ./internal/subscription ./internal/middleware ./internal/runtime ./internal/config ./internal/kms/vault` passed.
  - `git diff --check` passed.
  - Targeted `rg` found no remaining misleading current-runtime references for Claude/Gemini templates, quota day/plan enforcement, Router weighted load/fallback chains, all-admin-audit logging, current cost control, or old changelog verification wording. The remaining Claude/Gemini match is the subscription regression test that rejects them.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=9b8d7a8-truth-surface-cleanup-final BUILD_DATE=2026-06-20T00:00:00Z PORT=18111` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `306.03kB`.
    - Image `sha256:28168b95d1fc719ec22e5c8c194bbe5a5e5a06f425ff0c2d36e62664c2b5a584`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 9b8d7a8-truth-surface-cleanup-final, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture expert Archimedes found no release blocker after the patch and confirmed all four architecture should-fix items were closed: unsupported model exposure, quota wording, Router comment scope, and dependency/release-gate policy.
  - Security expert Halley found no release blocker after the patch and confirmed the Admin/cost-control should-fix items were closed.
  - Halley then identified two residual should-fix wording issues in Vault scaffold comments and `CHANGELOG.md` verification heading; both were fixed and the follow-up review confirmed no remaining blocker or should-fix.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 27 - Router Baseline Test Evidence

- Release-quality finding:
  - `v0.2.0` documents provider routing, model permission enforcement, body-size limiting, and stream flag detection as implemented baseline behavior.
  - The middleware package did not have dedicated Router behavior tests covering those contracts as release evidence.
  - This was a test evidence gap rather than a runtime behavior change.
- Fix:
  - Added `internal/middleware/router_test.go`.
  - Covered exact model permission selecting the expected provider and pool key.
  - Covered request body preservation by reading the body after Router runs and comparing it to the original bytes.
  - Covered explicit wildcard model permission allowing a known model.
  - Covered unpermitted models returning `403` before provider/key selection.
  - Covered missing model `400`, permitted model with no supporting provider `503`, and body limit `413`.
  - Did not update `CHANGELOG.md` because this is test-only and does not change user-visible runtime behavior.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test -count=1 ./internal/middleware` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=daaee65-router-baseline-tests BUILD_DATE=2026-06-20T00:00:00Z PORT=18109` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `302.94kB`.
    - Image `sha256:c920a4443ad6e339b043645e5ea865c5eb0d47b12bb29e86e0ed1e153badd679`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: daaee65-router-baseline-tests, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture expert Chandrasekhar first found two should-fix issues: the body-preservation test only checked `ContentLength`, and wildcard model permission lacked a success-path Router test.
  - The patch was updated to read and compare the preserved body bytes and add `TestRouterWildcardPermissionAllowsKnownModel`.
  - Chandrasekhar's follow-up read-only review confirmed both should-fix findings are resolved, found no new release blocker or should-fix, and accepted this test-only diff as `v0.2.0` router baseline release evidence.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 26 - Reserved Admin Scaffold Auth Hardening

- Security/truth-surface finding:
  - The main `v0.2.0` gateway does not mount Admin API routes, but the reserved `internal/admin` scaffold still ships in the repository.
  - Admin auth failures returned different client messages for missing versus invalid tokens.
  - The scaffold comparison helper returned before `crypto/subtle.ConstantTimeCompare` when lengths differed.
- Fix:
  - Added shared admin auth constants for the token header and generic failure message.
  - Changed missing and incorrect admin token responses to the same `admin authentication failed` message.
  - Changed provided-token comparison to hash both inputs with SHA-256, compare the fixed-length digests with `subtle.ConstantTimeCompare`, and preserve exact-length equality in the final result.
  - Added tests for missing, same-length wrong, short wrong, nil, and equal token cases.
  - Preserved the current fail-closed BYOK scaffold behavior: authenticated BYOK registration still returns `501` and does not store submitted keys.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- New `v0.2.0` behavior:
  - Admin API remains excluded from the main gateway runtime and is still not mounted by `cmd/aegis`.
  - If the scaffold is exercised directly in tests or future wiring, admin auth failure categories are not reflected to clients.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/admin` passed.
  - `rg -n "admin token required|invalid admin token|ConstantTimeEq|int32\\(len|admin authentication failed|X-Admin-Token" internal/admin CHANGELOG.md SECURITY.md docs` confirmed the old client-facing auth failure messages were removed and only the new generic message remains.
  - `git diff --check` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=c35c858-admin-auth-scaffold BUILD_DATE=2026-06-20T00:00:00Z PORT=18107` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `296.73kB`.
    - Image `sha256:1e146c6f4293e0de87185c9ba851f64b6261a123b8eea03a19877aeb9213c529`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: c35c858-admin-auth-scaffold, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture/security expert Hooke found no release-blocking or should-fix findings.
  - Hooke confirmed `cmd/aegis` still uses `runtime.NewServer`, the server mux still mounts only `/v1/` and `/health`, and no runtime/cmd code imports `internal/admin` or calls `RegisterRoutes`.
  - Hooke judged the fixed-length hash comparison conservative but not over-designed for the scaffold, and found no safety regression.
  - Mainline self-review corrected the changelog wording to avoid claiming missing-token requests enter the comparison path.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 25 - PII Redaction Baseline Test Evidence

- Release-quality finding:
  - `v0.2.0` documents regex-based PII request redaction as an implemented baseline, but the middleware package did not have dedicated tests for redact/detect/block/body-limit behavior.
  - This was a release evidence gap rather than a runtime behavior change.
- Fix:
  - Added `internal/middleware/redaction_test.go`.
  - Covered `ModeRedact` replacing an email before `next()`.
  - Covered `ModeDetect` preserving the original body while still allowing the request through.
  - Covered `ModeBlock` aborting when PII is detected.
  - Covered oversized request bodies aborting with `413`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/middleware` passed.
  - `git diff --check` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=1450032-pii-redaction-tests BUILD_DATE=2026-06-20T00:00:00Z PORT=18106` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `295.22kB`.
    - Image `sha256:f69b4bdfffdcf686af7faa0d5a976b0b9c027ea9d485de98fef9b762f29954c9`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 1450032-pii-redaction-tests, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Mainline self-review confirmed this is SUT behavior coverage only: the tests call the real `PIIRedaction` middleware and do not mock the scanner.
  - The initial attempt to assert private `RequestContext.abortBody` indirectly was removed because it would not have proven the real middleware output path.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 24 - Audit Virtual-Key ID Log Boundary

- Security/truth-surface finding:
  - Old `v0.2.0-rc` audit logs used the field name `virtual_key` while the value was actually the JWT `kid` / virtual-key ID, not the bearer virtual key token.
  - The safe logger did not treat the exact `virtual_key` field name as sensitive, so future code could accidentally log a bearer virtual key under the ambiguous field without defense-in-depth redaction.
- Fix:
  - Renamed audit metadata from `virtual_key` to `virtual_key_id`.
  - Added exact-field redaction for accidental `virtual_key` log attributes.
  - Preserved `virtual_key_id` as structural audit metadata so per-key investigation remains possible without logging bearer tokens.
  - Updated `SECURITY.md` and `CHANGELOG.md` to state the `v0.2.0` audit contract explicitly.
  - Added regression coverage for both the audit middleware field name and safe logger redaction/preservation behavior.
- New `v0.2.0` behavior:
  - Audit logs may record virtual-key IDs.
  - Bearer virtual keys logged under `virtual_key` are redacted.
  - Existing method, path, status, duration, token-count, provider, and model audit metadata remains unchanged.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/server ./internal/utils` passed.
  - `git diff --check` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=8efbd6d-audit-virtual-key-id BUILD_DATE=2026-06-20T00:00:00Z PORT=18105` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `291.83kB`.
    - Image `sha256:006fd9a5247a9262619182b5d15e7c1330feb11972671c6dda4ae1daae1e0009`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 8efbd6d-audit-virtual-key-id, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Architecture/security expert Noether found no release-blocking or should-fix issues, confirmed `ctx.VirtualKeyID` comes from the JWT `kid` and not the bearer token, and confirmed the production entrypoint uses `utils.NewAuditLogger`.
  - Noether also confirmed there is no audit capability loss: per-key tracing remains under `virtual_key_id`, while the ambiguous `virtual_key` field is now protected.
  - Mainline self-review confirmed the runtime no longer emits `"virtual_key":` and the remaining old-field references are tests, redaction config, planned admin response schema, and changelog wording.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 23 - Reserved TPM Token Retention Removal

- Security/architecture finding:
  - Old `v0.2.0-rc` behavior still inherited a `v0.1.0`-style reserved TPM reconciliation hook.
  - Even though non-zero TPM configuration and claims fail closed in `v0.2.0`, successful requests still appended `ctx.InputTokens + ctx.OutputTokens` into an in-memory `:tpm` window.
  - That state had no enforcement path, no read path, and no eviction path because TPM enforcement is reserved, making it a no-benefit process-lifetime memory growth surface.
- Fix:
  - Removed the post-`next()` reserved TPM token-accounting hook.
  - Removed `Limiter.RecordTokens`, the memory `:tpm` append implementation, and the unused `slidingWindow.window` field.
  - Added a package-private `rateLimiter` injection point only for testing the existing middleware behavior.
  - Added regression coverage proving that when `DefaultTPM=0` and `ctx.MaxTPM=0`, downstream `InputTokens`/`OutputTokens` updates do not cause any TPM limiter path; the runtime still executes only RPM and concurrency limiting.
  - Updated `CHANGELOG.md` under `v0.2.0 - Release Candidate`.
- New `v0.2.0` behavior:
  - TPM remains reserved and non-zero TPM still fails closed.
  - Token counts are still available as request metadata, but the rate limiter does not retain token-accounting state until TPM enforcement is actually implemented.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/middleware` passed.
  - `rg -n "RecordTokens|:tpm|Reserved hook" internal/middleware internal` returned no matches.
  - `git diff --check` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=290ab5f-tpm-token-retention-fix BUILD_DATE=2026-06-20T00:00:00Z PORT=18104` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `290.00kB`.
    - Image `sha256:5325c73e328435ba24de8ead18e3188090a7c7ebf5487cd1fe5b1493d3997ad1`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: 290ab5f-tpm-token-retention-fix, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Security expert A found the old reserved TPM retention to be release-before-fix because it appended per-token-count records with no enforcement/read/eviction path; it recommended stopping token retention rather than adding a cap to an unimplemented feature.
  - Architecture/security expert B found no release-blocking or should-fix issues after the fix, confirmed the `v0.2.0` old-to-new contract alignment, and judged the test injection point narrow enough because it remains package-private and does not expand the public API.
  - Mainline self-review confirmed this removes the only `RecordTokens`/`:tpm` runtime path while preserving existing non-zero TPM fail-closed behavior.
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

### Step 22 - Request ID Header Echo Hardening

- Security finding:
  - `RequestIDMiddleware` accepted and echoed any client-supplied `X-Request-ID` value.
  - This created an avoidable response-header and trace-metadata trust boundary risk for oversized, malformed, control-character, whitespace-padded, or non-ASCII request IDs.
- Fix:
  - Added a strict request ID acceptance boundary in shared `internal/requestid`.
  - Safe client request IDs are preserved only when they are non-empty, at most 128 bytes, trimmed, and contain only ASCII letters, digits, `-`, `_`, `.`, or `:`.
  - Unsafe values are replaced with generated `req_...` IDs.
  - Mapped safe upstream provider request IDs to `X-Upstream-Request-Id` instead of appending them to the gateway `X-Request-ID` response header.
  - Added regression tests for common safe ID formats, unsafe ID rejection, parsed HTTP header behavior, safe client ID preservation, unsafe client ID regeneration, and safe-only upstream request ID mapping.
  - Updated changelog under `v0.2.0 - Release Candidate`.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/requestid ./internal/server ./internal/proxy` passed.
  - `git diff --check` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=c884a7b-request-id-shared BUILD_DATE=2026-06-20T00:00:00Z PORT=18101` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `288.74kB`.
    - Image `sha256:d6787ff078060a7074d8415a70e2c077dabe0337b106340327bb1033420f71e3`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: c884a7b-request-id-shared, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Security architecture expert A initially found no blocking issue in client `X-Request-ID` validation, and identified the upstream `X-Request-Id` response-header collision risk. The final review confirmed no blocking or should-fix findings after upstream IDs were mapped to `X-Upstream-Request-Id` and filtered with the shared request ID safety contract.
  - Code review expert B initially found no blocking issue, and requested clearer parsed-header test coverage plus progress evidence. The final review confirmed the shared `internal/requestid` contract, parsed HTTP header test, raw header-map test naming, and upstream safe-only mapping have no remaining blocking or should-fix findings.
- Remaining gates before release-complete claim:
  - Restore an approved GitHub write credential path.
  - Push branch and verify GitHub Actions CI green on final remote SHA.
  - Create `v0.2.0` tag only after remote CI and final release artifact checks pass.

### Step 21 - Exact Egress Host Allowlist Matching

- Security finding:
  - Runtime startup validation and proxy request validation both used suffix matching for `egress.allowed_domains`.
  - An exact-looking entry such as `api.openai.com` therefore also allowed `tenant.api.openai.com`, which widened the outbound trust boundary unless operators knew about the implicit suffix behavior.
- Fix:
  - Added `internal/egress` as the shared host matching boundary for runtime and proxy validation.
  - Changed egress matching to exact-host by default.
  - Kept deliberate subdomain support through explicit `*.` wildcard entries, e.g. `*.openai.com`.
  - Updated architecture design, security policy, and changelog to describe exact-host and explicit-wildcard semantics.
  - Added regression coverage for exact host matching, implicit subdomain rejection, explicit wildcard acceptance, normalized host/URL entries, and substring bypass rejection.
- Verification:
  - `$HOME/.cache/codex-go/go1.26.4/bin/go test ./internal/egress ./internal/proxy ./internal/runtime` passed.
  - `ALLOW_DIRTY=1 make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passed.
  - `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=dd8bed9-exact-egress BUILD_DATE=2026-06-20T00:00:00Z PORT=18098` passed on `ssh ceo`.
  - `ceo-docker-smoke` evidence:
    - Host `Mac-mini.local`, `arm64`.
    - Docker server `29.1.3`, architecture `aarch64`.
    - Build context `282.65kB`.
    - Image `sha256:84d685f9bb202fce2c1a45c4cf99ad3abd1542db149dfdf4f0283e33817c5f3b`, `os=linux`, `arch=arm64`, `user=nonroot:nonroot`.
    - Binary: `ELF 64-bit LSB executable, ARM aarch64`.
    - Version output: `aegis v0.2.0-docker-test (commit: dd8bed9-exact-egress, built: 2026-06-20T00:00:00Z)`.
    - Runtime: `health={"status":"ok"}`, `unauth_status=401`, `readonly=true`, `user=nonroot:nonroot`, `/var/lib/aegis:volume`.
- Autoreview:
  - Security architecture expert A confirmed the old implicit suffix match was a release-before-fix issue and that exact-host default plus explicit `*.` wildcard is the correct release contract; it requested threat-model/module-boundary documentation, which was added.
  - Architecture compatibility expert B confirmed no blocking findings, no breakage to `aegis.example.json`, runtime assembly, or `ceo` Docker smoke; it recommended README/ARCHITECTURE discoverability text, which was added.
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
