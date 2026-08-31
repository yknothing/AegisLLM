# AegisLLM Review Remediation Worklog

## Status

| Field | Value |
| --- | --- |
| Work ID | `aegis-review-remediation-2026-07-15` |
| Historical baseline | `c553bb7` on `codex/aegis-architecture-refactor` |
| State | Historical remediation ledger; `CANDIDATE_HARDENED_NOT_RELEASE_READY` pending the `BLOCKED_BY_DECISION` artifact scope and fresh final evidence bound outside the candidate tree |
| Source review | Fable deep review attached by the operator |
| Execution mode | Evidence-first brownfield hardening; operator questions deferred to final handoff |

This file is the durable progress and decision record for the remediation. It
must distinguish historical findings from defects that still exist at the
current baseline. It is a tracked pre-freeze ledger, not the final release
evidence manifest. Final exact-SHA CI results and artifact digests must follow
the immutable external-manifest contract in `docs/release-plan-v0.2.1.md` so
recording them does not change and invalidate the candidate SHA.

## Intake Brief

- **Request summary:** Re-evaluate the Fable review against the current tree,
  refine the real product and architecture boundary, and implement the
  highest-priority safe work without waiting for interactive confirmation.
- **Source language:** `zh-Hans`
- **Artifact record language:** `en`
- **User presentation locale:** `zh-Hans`
- **Work type:** Tech Debt
- **Entry phase:** `03-planning`, with a discovery and architecture correction
  pass because the supplied review targets an older implementation state.
- **Intake mode:** `resume`
- **workflow_primary:** `agile-sprint`
- **workflow_overlays:** `brownfield`
- **Runtime context:** `standalone_validation_behind_trusted_ingress`
- **Exposure profile:** The binary is not a public-Internet DoS containment
  boundary. Its limiter is per authenticated virtual key; aggregate/source-IP/
  pre-authentication admission limits must come from the trusted ingress. The
  bundled config is a development smoke profile and listens on all interfaces.
- **Release target:** A single-process security-first LLM API gateway with an
  honest standalone validation baseline, not a production/scale claim.
- **Non-targets for this pass:** Enabling unfinished Redis, Vault, BYOK, quota,
  TPM, Anthropic, Gemini, or public Admin API capabilities.
- **Evidence references:** `README.md`, `ARCHITECTURE.md`,
  `docs/architecture-design.md`, `docs/threat-model.md`, current source/tests,
  fresh local commands, and three independent agent audits.
- **Key risks:** False confidence from applying stale findings to the current
  tree; security controls that silently fall back; a release gate that scans a
  different Go standard library than the shipped binary; and implementing a
  control plane before its trust model is approved.
- **Route:** `code-review` -> `system-design` -> `security-design` ->
  `task-breakdown` -> `tdd` -> `feature-development` -> `security-audit` ->
  `verification-before-completion`.

The operator explicitly asked the team to continue while they are offline and
to move confirmation items to the final handoff. That instruction is treated
as approval for reversible, test-backed hardening that preserves the existing
product boundary. Material control-plane, storage-format, and token-contract
expansions remain decision-gated.

## Problem Frame

The old scaffold mixed implemented code, disconnected components, and future
claims. The current `v0.2.0` line has already repaired much of that by wiring a
real runtime and failing closed for reserved capabilities. The remaining job is
not to rebuild every planned feature. It is to make the supported standalone
slice strict, reachable, observable, and verifiable while keeping future
enterprise capabilities explicitly out of scope.

### Constraints

- Security outranks compatibility with undocumented or unsafe behavior.
- No new runtime dependency without a separate security review.
- Provider keys, virtual keys, prompts, and completions must not enter logs.
- Existing `internal/` boundaries and the runtime composition root remain.
- Unsupported capability configuration must fail closed.
- Storage-format changes require migration and rollback design.

### Non-goals

- A public network Admin API in this remediation slice.
- A distributed/cluster control plane.
- Heuristic token counts used for quota, TPM, or billing decisions.
- Claims that local green checks make a release ready.

## Direction Options

### A. Harden the current standalone slice (recommended)

Keep the single binary and current interfaces. Repair fail-open defaults,
toolchain/release evidence, terminal composition, route surface, memory
retention, and the missing success-path proof. Add operator bootstrap only
after its CLI secret-input contract is reviewed.

This is the smallest reversible path to an honest and useful gateway.

### B. Implement the full enterprise promise now

Build Admin/BYOK, shared revocation, Vault, Redis, quota, and TPM together. This
would address the largest capability gaps but expands the trust surface before
the standalone baseline has a proven success path. Reject for this pass.

### C. Rewrite around a new gateway core

Replace the middleware pipeline with a new service or dependency-heavy gateway.
This discards tested security boundaries without evidence that the current
single-process architecture is the root problem. Reject.

## Fable Finding Reconciliation

| Original finding | Current status | Evidence summary |
| --- | --- | --- |
| Example duration strings fail to parse | Fixed | Custom duration decoding exists; fresh local smoke passes. |
| Egress substring matching is bypassable | Fixed | Parsed HTTPS URL plus normalized exact/explicit wildcard host matching. |
| Production runtime is an empty pipeline | Fixed | `runtime.NewServer` wires Auth through Proxy; exhausting any incorrectly composed chain now fails closed with `500`. |
| Router cannot read the model | Fixed | Bounded read-and-replace body path extracts model and preserves forwarding. |
| Request body can never be inspected safely | Fixed for the supported slice | The transport body has one owner; PII uses bounded token-level semantic processing and a capped canonical output, while Router and Adapter reuse the resulting buffer. Superseded and final owned byte buffers are zeroed. |
| JWT is unimplemented | Fixed baseline | HS256 is algorithm-locked and signature/issuer/time/claim checks exist; issuer and `key_source` are mandatory. |
| TPM/per-key controls silently do nothing | Fixed by enforcement or fail-fast | RPM/concurrency are wired; non-zero TPM/budget claims and configuration are rejected. |
| `0 = unlimited` concurrency rejects all | Fixed | Non-positive concurrency is treated as unlimited/fallback. |
| Limiter memory grows forever | Fixed for idle state | Idle RPM windows are pruned periodically and zero-concurrency trackers are deleted; active-cardinality capacity policy remains a future operational control. |
| SSE 64 KiB scanner limit | Fixed with explicit boundary | Scanner limit is 1 MiB and tested; larger single events fail explicitly. |
| Upstream hop-by-hop headers leak downstream | Fixed | Response headers use an allowlist. |
| Token/cost accounting is accurate | Not supported | Input usage is zero and streaming output is heuristic; quota/TPM remain disabled. |
| Admin/BYOK/quota/subscription are disconnected | Intentionally reserved | Current docs and validation fail closed instead of claiming support. |

## Current Findings and Task Board

Status tokens: `DONE`, `IN_PROGRESS`, `READY`, `BLOCKED_DECISION`, `DEFERRED`.

| ID | Priority | Status | Slice | Done criteria |
| --- | --- | --- | --- | --- |
| T01 | P0 | DONE | Reconcile stale review with current HEAD | Each major assertion classified with current code and fresh command evidence. |
| T02 | P0 | DONE | Align build and security-scan Go toolchain | CI and Docker builder use pinned Go 1.26.6; source and binary-mode `govulncheck` are required gates. Go 1.26.5 evidence is historical and stale after the 2026-08 standard-library disclosures. |
| T03 | P0 | DONE | Reject unknown configuration fields | Root and nested config typos fail startup; valid example still loads. |
| T04 | P0 | DONE | Fail closed for issuer and key source | Empty configured issuer and missing JWT `key_source` are rejected with defense-in-depth at Auth and KMS boundaries. |
| T05 | P0 | DONE | Fail closed when the business pipeline has no terminal | A missing or exhausted terminal path cannot return an implicit empty `200`. |
| T06 | P1 | DONE | Narrow the supported ingress contract | Only `POST /v1/chat/completions` enters the gateway pipeline. |
| T07 | P1 | DONE | Reclaim idle in-memory limiter state | Idle RPM windows and zero-concurrency trackers are evicted and tested; active cardinality remains traffic-bound. |
| T08 | P1 | DONE | Prove one hermetic proxy success path | A TLS 1.3 fake provider test covers Auth -> PII -> Router -> file KMS -> Adapter -> header filtering -> Proxy. |
| T09 | P1 | DONE | Make request body ownership and semantic processing bounded | The transport body is buffered once after auth; PII tokenization/canonical output has independent byte and structure budgets; downstream transformations reuse the owned result. |
| T10 | P1 | DONE | Separate provider health from local gateway failures | Provider 429/5xx, dial/TLS/timeout, and upstream-read failures affect health; KMS/adapter/policy and client-cancel/write failures do not. |
| T11 | P0 | DONE | Make the published gateway happy path operator-reachable | Offline CLI and real-process auth/provisioning smoke passed; three independent reviewers accepted. |
| T12 | P1 | DONE | Bind local KMS ciphertext to key identity | v2 keyID AAD, locked backup migration, strict-v2 post-migration floor, and rollback contract passed independent acceptance. |
| T13 | P1 | DONE | Make revocation operational | Single-host snapshot/poller, bounded fail-closed behavior, SLA, and Docker valid-auth/revoke gates passed independent acceptance. |
| T14 | P2 | DEFERRED | Implement trustworthy usage/quota/TPM | Provider usage parsing plus atomic reserve/reconcile must precede enforcement. |

## Architecture Corrections

1. **Truth before breadth.** Reserved capabilities remain impossible to enable
   accidentally. Documentation must describe the supported standalone slice,
   not the interface inventory.
2. **One transport-body owner with bounded semantic transformation.** Auth runs
   without body access. The next stage reads once; PII tokenization and its
   canonical output have tighter independent budgets, and routing/adapters
   reuse the owned result. Only the provider response is streamed.
3. **Explicit terminal semantics.** A gateway pipeline must either abort or
   produce a terminal response. Falling off the chain is an internal error.
4. **Structured upstream outcomes.** Provider circuit health is updated only by
   transport/provider outcomes, never by local KMS, adapter, or policy errors.
5. **Security configuration is a schema.** Unknown JSON fields, empty security
   identities, and missing privilege-source claims are invalid.
6. **Artifact-equivalent verification.** Source checks, local binaries, and
   container binaries must use an aligned patched Go toolchain. Binary-mode
   vulnerability evidence complements source-mode scanning.
7. **Control plane stays separate.** Provider-key seeding, virtual-key issuance,
   revocation, BYOK, and quota are privileged operations. They must not be
   smuggled into the public `/v1` data plane.

## Historical Fresh Evidence Log (STALE for final release)

These entries describe the remediation snapshot at the time they were
recorded. They are useful historical diagnostics, but none is current final
release evidence and none may be rebound to a later candidate implicitly.

| Check | Result |
| --- | --- |
| `git status --short --branch` | Clean; branch aligned with origin at audit start. |
| `git diff --check` | Pass. |
| `go test -count=1 ./...` | Pass on local Go 1.26.4 before remediation. |
| `go vet ./...` | Pass on local Go 1.26.4 before remediation. |
| `go test -race ./...` | Pass in independent quality audit. |
| `gosec -quiet ./...` | Pass in independent security/quality audits. |
| `make local-smoke` | Pass: health `200`, unauthenticated data-plane request `401`. |
| `make release-preflight` | **Fail:** `GO-2026-5856` affects Go 1.26.4; fixed in Go 1.26.5. |
| `GOTOOLCHAIN=go1.26.5 make govulncheck-binary` | **STALE / HISTORICAL:** passed against the vulnerability database available at that time; a later database reports five reachable standard-library vulnerabilities for Go 1.26.5. |
| `GOTOOLCHAIN=go1.26.5 go test -count=1 ./...` | **STALE / HISTORICAL:** passed after remediation, including the hermetic TLS 1.3 runtime success path. |
| `GOTOOLCHAIN=go1.26.5 go vet ./...` | **STALE / HISTORICAL:** passed after remediation. |
| `git diff --check` | Pass after remediation. |
| `ALLOW_DIRTY=1 GOTOOLCHAIN=go1.26.5 make release-preflight GO=go VERSION=v0.2.1-rc-audit` | **STALE / ITERATION_ONLY:** pass: full quality/security gates, local health `200`, and unauthenticated data-plane `POST` `401`; the dirty override makes this ineligible as a final gate. |
| Hermetic runtime/proxy TLS success tests | Pass with `-race -count=10`. |
| Dedicated Mac Mini Docker build/read-only smoke | Pass on `ceo`: Linux/arm64 static binary, `nonroot:nonroot`, correct entrypoint/cmd, read-only root, health `200`, unauthenticated POST `401`, isolated volume, and cleanup confirmed. The first build hit a transient Alpine package extraction I/O error; one bounded retry passed without code changes. |
| Local Docker / remote CI | Local daemon remains unavailable; CI has not run for this uncommitted diff. |
| Existing GitHub CI | Historical green only; predates the current vulnerability database result. |

## Historical v0.2.1 Acceptance Snapshot — 2026-07-16 (STALE)

The entire snapshot below is historical technical evidence. In particular, its
dirty-tree marker and image digest do not identify or attest the current clean
candidate and must not be presented as final release evidence.

| Surface | Historical evidence |
| --- | --- |
| Candidate identity | **STALE / HISTORICAL:** changed/untracked content marker `a4b338fb109963c85ab4c33c23eb7cd337a789cf1a4e135116428b3a7beb4aee` before the evidence-only worklog update; it is not a clean candidate commit SHA. |
| Local release preflight | **STALE / HISTORICAL:** passed on Go 1.26.5 using the vulnerability database available at that time; later disclosure data invalidates its vulnerability-free claim. |
| Go compatibility | `GOTOOLCHAIN=go1.22.4 go test ./... -count=1` passed. |
| Local auth/revocation smoke | Valid token reached request parsing (`400` malformed body), durable revoke committed generation 2, the same token became `401`, and unauthenticated traffic remained `401`. |
| Revocation adversarial checks | Malformed KMS filename failed closed; near-4 MiB snapshot mutation was rejected without changing the committed snapshot; three 500 ms poller trials observed revocation within at most 503 ms, below the 750 ms published bound. |
| Final Mac Mini Docker gate | **STALE / HISTORICAL:** the 2026-07-16 run passed on `ceo`; image `sha256:83d469876262af2b3fa610b014bc3db1bc8355bb99a95697410d21005105a5d7`, Linux/arm64 static ELF, `nonroot:nonroot`, read-only root, health `200`, valid-auth `400`, revoke generation 2, revoked `401`, unauthenticated `401`, isolated volume, cleanup complete. This digest is not bound to the current candidate. |
| Independent security review | **HISTORICAL TECHNICAL REVIEW:** ACCEPT; P0=0, P1=0. Strict-v2, bounded secret input, migration reporting/locking, key-ID bound, rollback truth, and Go 1.26.5 security scans accepted. |
| Independent runtime architecture review | **HISTORICAL TECHNICAL REVIEW:** ACCEPT; P0=0, P1=0. Provider identity, backend error semantics, module direction, KMS cutover/locking, revocation boundary, and rollback contract accepted. |
| Independent quality review | **HISTORICAL TECHNICAL REVIEW:** ACCEPT; P0=0, P1=0. Full gates, edge fixtures, SLA, CLI, local process, and final Mac Mini evidence accepted. |
| Not yet verified/published at snapshot time | GitHub Actions on an exact pushed commit, a clean release commit, annotated `v0.2.1` tag, tag push, and published release required a later explicit publish request. This row records the 2026-07-16 state only. |

## Current Iteration Evidence — 2026-08-20 (Not Final)

Every entry below was produced while the current candidate tree was dirty. It
is `ITERATION_ONLY`, not release evidence, and must be rerun after protected-PR
merge on the clean frozen `main` commit.

| Check | Iteration result |
| --- | --- |
| Latest vulnerability database with Go 1.26.5 | **FAIL / STALE TOOLCHAIN:** five reachable standard-library vulnerabilities; all earlier Go 1.26.5 vulnerability-free claims are stale. |
| `GOTOOLCHAIN=go1.26.6 make security` | **PASS / ITERATION_ONLY:** source and binary govulncheck reported `No vulnerabilities found.` and gosec passed. |
| Full-SHA build identity contract before repair | **RED as expected:** `make -n local-smoke` propagated abbreviated `COMMIT=e4805e6`, and both smoke scripts derived `HEAD` with `git rev-parse --short`. |
| Full-SHA build identity contract after repair | **PASS / ITERATION_ONLY:** Makefile dry-runs propagate the full 40-character HEAD SHA; clean-mode local and CEO scripts reject short/non-hex values, while dirty override accepts only the exact `workspace-<full-sha>` identity and labels it `ITERATION_ONLY`. |

## Current Release Evidence Disposition

- **`BLOCKED_BY_DECISION`:** the operator has not selected source tag only,
  binaries, container images, or an explicit combination as the published
  artifact set. No option is selected by this worklog.
- The dirty-tree marker, Mac Mini image digest, local gates, and technical review
  dispositions above are `STALE` for final-release purposes.
- No final immutable external evidence manifest is recorded in this tracked
  file. After protected-PR merge and clean candidate freeze, the manifest must
  be created outside the candidate Git tree and bind the exact commit, selected
  artifacts, final gate runs, and QA evidence. A real independent human must
  then issue a detached approval over the finalized manifest digest, candidate
  SHA, and ordered artifact-digest tuple as specified in
  `docs/release-plan-v0.2.1.md`; bootstrap-owner or agent assent does not count.
- Independent-human governance, immutable remote `v*` tag rules, release and
  rollback owner assignments, abort authority, and the UTC release window are
  unresolved external/coordination prerequisites.
- Until the artifact decision and manifest contract are satisfied, the only
  defensible terminal state is `CANDIDATE_HARDENED_NOT_RELEASE_READY`.

## Decision Queue for Operator Handoff

1. **Resolved:** implement a standalone offline Bootstrap CLI; defer the
   network Control Plane.
2. **Resolved:** implement a versioned KMS envelope that binds ciphertext to
   key ID, dual-reads legacy data, single-writes v2, and migrates explicitly
   from an encrypted backup.
3. **Resolved:** implement durable single-host revocation first; keep a stable
   checker seam for a later reviewed multi-instance backend.
4. **Resolved:** iterate as `v0.2.1`; `v0.2.0` points to an older commit and
   must not be moved.
5. **`BLOCKED_BY_DECISION`:** choose the exact published artifact set (source
   tag only, binaries, container images, or a named combination) and the
   immutable external manifest storage/retention mechanism before final freeze.
6. **`BLOCKED_EXTERNAL`:** install immutable remote `v*` tag rules and add a
   real independent human QA/release approver; bootstrap-owner and agent review
   are technical evidence only.
7. **`BLOCKED_BY_ASSIGNMENT`:** name the release owner, rollback owner, abort
   authorities, UTC release window, and required communication contacts before
   the protected candidate PR is merged.

## v0.2.1 Expert Consensus Record

- **KMS adversarial review:** rejected nil AAD, direct hard cutover, and any
  v2-authentication-failure fallback to legacy. Accepted a strict versioned
  envelope, keyID-bound AAD, explicit offline migration, strict-v2 cutover,
  and backup-based rollback.
- **Revocation independent acceptance design:** rejected process memory,
  startup-only reload, per-request disk reads, and a first-release append-only
  log. Accepted versioned atomic snapshot + kernel writer lock + 500 ms poller
  + immutable request-path lookup, with corruption/deletion and
  runtime-observed rollback failing closed. Cross-restart rollback remains a
  documented single-file limitation.
- **CLI architecture review:** accepted the same-binary offline approach and
  required provider-ID-to-key resolution, bounded non-TTY stdin, explicit
  exclusive `0600` token output or explicit stdout, shared KMS construction,
  migration dry-run/apply, and compatibility tests for existing server flags.
