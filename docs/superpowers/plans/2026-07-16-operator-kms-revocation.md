# AegisLLM v0.2.1 Operator, KMS, and Revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a supported offline operator workflow, keyID-bound local-KMS storage, and durable single-host virtual-key revocation.

**Architecture:** `cmd/aegis` remains a thin process shell; `internal/operator` coordinates privileged offline use cases. Local KMS uses a dual-read/single-write versioned envelope, while `internal/revocation` owns a locked atomic snapshot and immutable polling reader consumed by Auth.

**Tech Stack:** Go standard library, AES-256-GCM, strict JSON, atomic filesystem rename/fsync, platform kernel file lock, existing middleware/runtime interfaces.

---

No commits are included in this plan because the current branch already holds
an uncommitted remediation set and the operator did not request a commit. Each
task must nevertheless end in a clean focused diff and fresh verification.

### Task 1: Configuration contract

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`
- Modify: `aegis.example.json`

- [x] Write failing tests for strict `auth.revocation` decoding, file backend/path/refresh bounds, 24h default TTL, and operator config parsing without unrelated secret preflight.
- [x] Run `GOTOOLCHAIN=go1.26.5 go test ./internal/config -run 'Revocation|Operator|DefaultToken' -count=1` and observe the expected missing-field/type failures.
- [x] Add `RevocationConfig`, duration decoding, validation, defaults, and a structural operator loader while preserving normal server fail-fast secret checks.
- [x] Re-run the focused command and require `ok`.

### Task 2: Virtual-key issuance contract

**Files:**
- Create: `internal/virtualkey/virtualkey.go`
- Create: `internal/virtualkey/virtualkey_test.go`
- Modify: `internal/middleware/auth.go`
- Test: `internal/middleware/auth_test.go`

- [x] Write failing tests proving issued HS256 tokens validate with exact issuer/models/limits, generated `kid` values are non-empty and distinct, TTL cannot exceed config maximum, and reserved BYOK/TPM/budget values remain rejected.
- [x] Run `GOTOOLCHAIN=go1.26.5 go test ./internal/virtualkey ./internal/middleware -run 'Issue|Validate|Auth' -count=1` and observe missing-package/API failure.
- [x] Move the shared claims/sign/validate contract to `internal/virtualkey`; keep middleware aliases where they preserve source compatibility; use constant-time signature comparison and zero caller-owned signing-key copies.
- [x] Re-run focused tests and require `ok`.

### Task 3: KMS v2 envelope

**Files:**
- Modify: `internal/kms/local/local.go`
- Test: `internal/kms/local/local_test.go`

- [x] Write failing tests for v2 header/AAD round-trip, cross-key blob swap rejection, stripped-header downgrade rejection, malformed/unknown v2 rejection, legacy nil-AAD read, and new-write format detection.
- [x] Run `GOTOOLCHAIN=go1.26.5 go test ./internal/kms/local -run 'Envelope|AAD|Legacy|Swap|Downgrade' -count=1` and observe failures against the raw legacy writer.
- [x] Implement fixed-prefix/header plus bounded keyID AAD, strict v2 parsing, a bounded dual-read migration window, strict-v2 cutover, and no authentication-failure fallback.
- [x] Re-run focused tests and require `ok`; then run the entire KMS package with `-race`.

### Task 4: Offline KMS migration

**Files:**
- Modify: `internal/kms/local/local.go`
- Modify: `internal/kms/local/file.go`
- Test: `internal/kms/local/local_test.go`
- Create: `internal/kms/factory/factory.go`
- Create: `internal/kms/factory/factory_test.go`
- Create: `internal/operator/operator.go`
- Create: `internal/operator/operator_test.go`

- [x] Write failing tests for required empty backup directory, encrypted backup completeness before rewrite, legacy-only migration, v2 idempotence, partial-failure reporting, and plaintext zeroing.
- [x] Run `GOTOOLCHAIN=go1.26.5 go test ./internal/kms/local ./internal/operator -run 'Migrate|Backup' -count=1` and observe missing API failure.
- [x] Add a shared local-KMS factory, an offline/single-writer migration API, dry-run/apply modes, and operator coordinator; every source replacement must remain atomic and every decrypted buffer must close/zero.
- [x] Re-run focused tests and require `ok`.

### Task 5: Durable local revocation

**Files:**
- Create: `internal/revocation/revocation.go`
- Create: `internal/revocation/revocation_test.go`
- Create: `internal/revocation/lock_unix.go`
- Create: `internal/revocation/lock_unsupported.go`
- Modify: `internal/middleware/auth.go`
- Test: `internal/middleware/auth_test.go`
- Modify: `internal/runtime/runtime.go`
- Test: `internal/runtime/runtime_test.go`

- [x] Write failing tests for init, strict snapshot schema, `0600`/`0700`, serialized concurrent union, idempotent non-shortening retention, poll visibility, restart persistence, corruption/deletion degraded state, valid recovery, and running-reader lower-generation rollback rejection.
- [x] Run `GOTOOLCHAIN=go1.26.5 go test ./internal/revocation ./internal/middleware ./internal/runtime -run 'Revocation|Revoke|Degraded|Rollback' -count=1` and observe missing API/behavior failures.
- [x] Implement the writer lock and atomic durable snapshot, bounded strict reader, immutable atomic state, poller lifecycle, error-returning Auth checker, generic `503`, and runtime shutdown hook.
- [x] Re-run focused tests, then `GOTOOLCHAIN=go1.26.5 go test -race ./internal/revocation ./internal/middleware ./internal/runtime -count=1`.

### Task 6: Operator command surface

**Files:**
- Create: `cmd/aegis/operator.go`
- Create: `cmd/aegis/operator_test.go`
- Modify: `cmd/aegis/main.go`
- Modify: `internal/operator/operator.go`
- Test: `internal/operator/operator_test.go`

- [x] Write failing parser/process-smoke tests for all five commands, provider-ID resolution, replace protection, bounded non-TTY stdin, explicit `--out`/`--stdout`, exclusive `0600` output, stdout/stderr separation, legacy server flags, and non-zero failure exits without secret reflection.
- [x] Run `GOTOOLCHAIN=go1.26.5 go test ./cmd/aegis ./internal/operator -run 'Operator|ProviderKey|VirtualKey|Revocation|Migrate' -count=1` and observe missing command failures.
- [x] Implement the smallest `flag.FlagSet`-based command tree and operator use cases. Do not add a CLI framework dependency.
- [x] Re-run focused tests and require `ok`.

### Task 7: v0.2.1 operational truth

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `SECURITY.md`
- Modify: `REVIEW.md`
- Modify: `docs/architecture-design.md`
- Modify: `docs/module-boundaries.md`
- Modify: `docs/threat-model.md`
- Create: `docs/release-plan-v0.2.1.md`
- Modify: `docs/README.md`
- Modify: `Dockerfile`
- Modify: `scripts/local_smoke.sh`
- Modify: `scripts/ceo_docker_smoke.sh`
- Modify: `scripts/release_preflight.sh`

- [x] Update the truth surface to `v0.2.1`, retain `v0.2.0` as historical, document CLI secret handling, KMS migration/rollback, revocation SLA/degraded semantics, and the multi-instance deferral.
- [x] Extend local and Docker smoke flows to initialize revocation state with the final binary before server start and prove valid-auth to revoke behavior.
- [x] Run `rg -n 'process-local revocation|v0\.2\.0-rc|out-of-band KMS seed' README.md ARCHITECTURE.md SECURITY.md REVIEW.md docs scripts` and resolve stale current-state claims without rewriting historical records.

### Task 8: Independent acceptance and release gates

**Files:**
- Modify: `docs/review-remediation-2026-07-15.md`

- [x] Assign security, runtime architecture, and quality reviewers who did not write the implementation; require file/line findings and explicit acceptance/rejection.
- [x] Fix every accepted P0/P1 finding and rerun the narrow failing proof first.
- [x] Run `git diff --check`, `gofmt`, focused `-race` tests, `go vet`, lint, gosec, source/binary govulncheck, and `ALLOW_DIRTY=1 GOTOOLCHAIN=go1.26.5 make release-preflight GO=go VERSION=v0.2.1-rc-audit`.
- [x] Run `ALLOW_DIRTY=1 make ceo-docker-smoke VERSION=v0.2.1-docker-audit` on the dedicated Mac Mini and record the exact image/platform/nonroot/read-only/health/auth/revocation evidence.
- [x] Append passed and unverified surfaces to the remediation worklog. Do not create a tag, commit, push, or release without a separate operator request.
