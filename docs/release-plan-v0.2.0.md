# AegisLLM v0.2.0 Release Plan

## Status

Current decision: **Go for the `v0.2.0` supported release tag**.

The `v0.2.0` tag may be created only after all release gates below are complete
for the exact commit being tagged. Do not move `aegis:latest` unless the Docker
image is built from that tagged commit and passes the same release gates.

## Scope

Included in `v0.2.0`:

- Runtime architecture baseline for the microkernel + middleware pipeline.
- HS256 virtual-key validation with fail-closed model permission checks.
- In-memory request/concurrency rate limiting.
- Local encrypted file-backed KMS for standalone validation.
- OpenAI-compatible provider path for `openai` and `deepseek`.
- HTTPS egress allowlist validation.
- PII redaction baseline.
- Distroless non-root Docker image with read-only runtime smoke coverage.
- Reproducible release gate scripts and GitHub Actions workflow.

Explicitly excluded:

- Production Admin API key issuance, revocation, and storage flows.
- BYOK key-source runtime before owner/provider binding exists.
- Vault KMS runtime backend.
- Redis/distributed rate limiting.
- Quota, budget, and TPM enforcement.
- RS256/JWKS virtual-key validation.
- Anthropic/Gemini protocol adapters.
- Production support commitment for `v0.2.0` before tag and remote CI green.

## Release Gates

All gates are required before tag creation:

1. Local worktree is clean on `codex/aegis-architecture-refactor`.
2. `make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local` passes with uncached Go tests and local process smoke.
3. `make local-smoke GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local COMMIT=<sha> PORT=<free-port>` passes against the exact clean candidate SHA.
4. `make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=<sha> BUILD_DATE=<utc-rfc3339> PORT=<free-port>` passes on `ssh ceo` against the exact clean candidate SHA.
5. Branch is pushed to GitHub without rewriting the local clean commit sequence.
6. GitHub Actions CI is green for the exact commit that will be tagged.
7. `SECURITY.md` still says no stable version is supported before the tag.
8. `CHANGELOG.md` and README describe the release candidate truthfully.
9. Release owner, verifier, and approver are assigned by name before the tag.

## Owners and Communication

- Release owner: `yknothing`, the GitHub repository administrator for `yknothing/AegisLLM`.
- Verification owner: Codex execution thread running local release gates, `ceo` Docker smoke, and GitHub Actions status checks.
- Approver: `yknothing`, repository maintainer with authority to accept the excluded capabilities above.

Communication moments:

- Before tag: post the candidate SHA, local gate output summary, `ceo` Docker smoke summary, and GitHub Actions run URL.
- At tag: publish release notes from `CHANGELOG.md` and state that unsupported capabilities remain planned work.
- After tag: record final SHA, tag URL, GitHub Actions run URL, and Docker image tag policy result.

## Abort Conditions

Abort or pause release if any condition occurs:

- Remote branch cannot be pushed with approved credentials.
- GitHub Actions fails on the exact candidate SHA.
- Local release preflight or `ceo` Docker smoke fails after the final code change.
- A security finding shows request/response body logging, plaintext key storage, missing credential zeroing, unsafe egress, or unsupported capability fail-open behavior.
- Documentation implies stable support before the tag exists.
- Release owner, verifier, or approver is not assigned.

## Rollback

Before tag creation, rollback is simply "do not release"; keep `v0.2.0`
untagged. If a tag is created accidentally before gates pass, delete the remote
tag and publish a correction that no supported release exists. Do not move
`aegis:latest` unless a supported release has passed all gates.

After tag creation, fixes must land as a new patch release candidate rather than
rewriting the signed release history.

## Success Criteria

The release can be called complete only when:

- The final tagged commit is present on GitHub.
- GitHub Actions is green for that exact commit.
- The `v0.2.0` tag exists and points to that commit.
- Release notes, security support status, and Docker tag policy are consistent.
- The final release evidence is appended to `tmp/refactor-AegisLLM-v0.2.0.md`.
