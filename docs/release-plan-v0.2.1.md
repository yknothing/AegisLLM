# AegisLLM v0.2.1 Release Plan

## Decision

Current state: **candidate implementation, not yet tagged or published**.

`v0.2.1` may be released only after the final candidate passes local and Mac
Mini Docker gates, three independent reviewers accept the implementation, the
branch is committed/pushed by explicit operator request, and GitHub Actions is
green on the exact release commit. The existing `v0.2.0` tag must not move.

## Included

- Same-binary offline Operator CLI for revocation initialization, configured
  provider-key import, supported pool virtual-key issuance/revocation, and KMS
  migration inspection/application.
- Provider-key input only through bounded non-terminal stdin; virtual-key
  output only through explicit stdout or exclusive owner-only file output.
- Local KMS v2 envelope with keyID-bound AAD, strict version parsing, an
  explicit legacy compatibility window, encrypted-backup migration, and a
  strict-v2 post-migration format floor.
- Durable single-host revocation with versioned JSON snapshot, kernel writer
  lock, atomic fsync/rename, bounded polling reader, in-memory request lookup,
  fail-closed corruption/deletion behavior, and running-reader rollback
  detection.
- 24-hour default maximum virtual-key lifetime.

## Explicitly Excluded

- Network Control Plane or mounted Admin API.
- Multi-host/shared-filesystem revocation.
- Redis, Vault, BYOK, quota, TPM, RS256, Anthropic, or Gemini runtime support.
- Moving or retagging `v0.2.0`.

## Required Gates

1. `git diff --check`
2. `GOTOOLCHAIN=go1.26.5 go test -count=1 ./...`
3. `GOTOOLCHAIN=go1.26.5 go test -race -count=1 ./...`
4. `GOTOOLCHAIN=go1.26.5 go vet ./...`
5. repository lint, gosec, source govulncheck, and final-binary govulncheck
6. `ALLOW_DIRTY=1 GOTOOLCHAIN=go1.26.5 make release-preflight GO=go VERSION=v0.2.1-rc-audit`
7. `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.1-docker-audit`
8. Independent security, runtime-architecture, and quality reviews with no open
   accepted P0/P1 findings.
9. After an explicit publish request: clean commit, push, final GitHub Actions
   green, annotated `v0.2.1` tag, and tag push.

## Storage Migration and Rollback

New installs keep `kms.local.minimum_envelope_version=2`. For an existing
legacy store, stop every KMS writer, set the field to `1`, then run
`aegis operator kms migrate --dry-run`. Apply requires a new backup directory
and copies every encrypted blob before any legacy rewrite. The CLI also takes a
shared local KMS operator lock, but older binaries and custom writers may not,
so no provider-key import or other KMS mutation may run during apply. Run the
dry-run again, require `legacy=0`, set the field to `2`, restart, and complete
the auth/provider smoke. The backup must be retained through the release
rollback window.

An older binary cannot read v2 writes. Rollback after migration therefore
requires stopping all gateway/operator processes, restoring the complete
pre-migration encrypted backup, and restoring the complete pre-v0.2.1 config
before deploying the older binary. This config restoration is mandatory:
v0.2.0 does not implement the semantics of
`kms.local.minimum_envelope_version` or `auth.revocation` and may silently
ignore those nested fields, so mixing the new config with the old binary is not
a supported rollback. Restore the matching pre-v0.2.1 auth/storage state
required by the old config, then repeat health/auth/provider smoke checks. Any
provider keys imported after the backup must be re-provisioned explicitly.

## Revocation Operational Contract

- Initialize state once with `aegis operator revocation init` before server
  start.
- A successful revoke reports the durable generation and a conservative
  `visible_by` time; local gateways must reject the `kid` by that bound.
- Snapshot failure never falls back to an empty revocation set.
- A running reader detects generation rollback. Restoring an older valid
  snapshot before restart is outside the single-file design's detection
  boundary; restore procedures must merge the union of all unexpired
  tombstones rather than choosing an older copy.
- The local backend is supported only on a single host and local filesystem.

## Evidence Record

Final command output, image identity, architecture, nonroot/read-only status,
health/auth results, independent reviewer dispositions, and unverified surfaces
must be appended to `docs/review-remediation-2026-07-15.md` before release.
