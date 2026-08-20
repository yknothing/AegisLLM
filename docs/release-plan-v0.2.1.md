# AegisLLM v0.2.1 Release Plan

## Decision

Release state: **not yet approved, tagged, or published**. This tracked file is
the pre-freeze release plan, not the final evidence artifact.

`v0.2.1` may be released only from a commit already merged into protected
`main`. After that merge, the exact resulting `main` commit must be checked out
cleanly, frozen, and used for every ceo-hosted test, Linux rollback, technical
review, and GitHub Actions gate. A real independent human must then approve the
finalized external evidence tuple as described below. The existing `v0.2.0`
tag must not move.

All candidate-bound tests, lint, race, smoke, and release-preflight execution
for this release must run on the dedicated test server reached through
`ssh ceo` (including its controlled Linux containers where required).
Developer-workstation results are feedback only and must never be recorded as
release evidence. GitHub Actions also runs an explicitly unverified bootstrap
preflight for technical feedback; that CI invocation is never candidate-bound
release evidence or approval.

The published artifact set is **`BLOCKED_BY_DECISION`**. Before candidate
freeze, the operator must explicitly choose source tag only, binaries,
container images, or a named combination. This plan does not make that product
and supply-chain decision implicitly. With the current workflows,
`source_tag_only` is the only scope that does not first require a new artifact
factory: CI and independent QA build disposable validation binaries/images and
do not retain or promote the exact tested bytes. Selecting any built-artifact
scope therefore requires build-once/test-by-digest/promote-the-same-bytes,
SBOM, signature, and provenance work before candidate freeze.

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

## External Governance Prerequisites

The release remains `BLOCKED_EXTERNAL` until all of the following are true:

- a real independent human QA/release approver has the intended repository or
  team role and can perform the required protected review; the bootstrap owner,
  candidate author/last pusher, technical agent, or agent reviewer does not
  satisfy this role;
- an active remote tag ruleset covers `v*`, forbids tag update and deletion,
  and has no routine bypass path for the release operator; and
- the operator has verified the narrowly scoped credentials needed to publish
  the immutable tag, external manifest, and detached attestations.

These are external controls. Repository text may record their required state,
but cannot claim they are installed without fresh remote evidence.

## Release Coordination Record

All placeholders below must be resolved before the protected candidate PR is
merged:

| Field | Required value |
| --- | --- |
| Release owner | `BLOCKED_BY_ASSIGNMENT`: named human coordinating merge, freeze, gates, and publication; cannot self-satisfy independent approval |
| Independent release approver | `BLOCKED_EXTERNAL`: real independent human defined above |
| Rollback owner | `BLOCKED_BY_ASSIGNMENT`: named human with backup-restore access and authority to execute rollback |
| Abort authority | Release owner, independent approver, and rollback owner may each stop publication; only the release owner may resume after all blockers are cleared |
| Release window | `BLOCKED_BY_SCHEDULE`: explicit UTC start/end with rollback-owner coverage through the rollback window |

Required communication points are: before protected-PR merge (scope, owners,
window, and abort conditions); after final gates (candidate and finalized
manifest digest sent for independent approval); immediately before publication
(detached approval confirmed); after publication (tag, manifest URI, and smoke
result); and on abort or rollback (authority, reason, current state, and next
decision time).

## Required Gates

1. Resolve the `BLOCKED_BY_DECISION` artifact set, all coordination placeholders,
   and all external governance prerequisites above.
2. Integrate every candidate-affecting change through the protected `main` PR
   path with required checks and a protected human review. A PR-head or
   synthetic merge SHA is not the final release candidate.
3. After the PR is merged, update the local checkout to the resulting remote
   `main` commit. Record its full 40-character lowercase hex SHA as
   `candidate_sha`; require `git status --porcelain --untracked-files=all` to be
   empty, then freeze it. Any later candidate-tree change restarts at gate 2.
   Transfer that exact clean tree to the dedicated `ssh ceo` test environment;
   gates 4 through 11 must execute there, not on a developer workstation. An
   external verifier/materializer must then produce the no-following, read-only
   candidate directory with sanitized Git metadata and the detached identity
   lock used by gates 9 and 10. Repository scripts do not create or approve
   those external identity inputs.
4. `git diff --check`
5. `GOWORK=off GOFLAGS=-mod=readonly GOENV=off GOTOOLCHAIN=local /absolute/path/to/go1.26.6/bin/go test -count=1 ./...`
6. `GOWORK=off GOFLAGS=-mod=readonly GOENV=off GOTOOLCHAIN=local /absolute/path/to/go1.26.6/bin/go test -race -count=1 ./...`
7. `GOWORK=off GOFLAGS=-mod=readonly GOENV=off GOTOOLCHAIN=local /absolute/path/to/go1.26.6/bin/go vet ./...`
8. repository lint, gosec, source govulncheck, and final-binary govulncheck
9. From a canonical external driver directory outside the read-only candidate
   on `ssh ceo`, run the script directly through a sterile launcher:

   ```bash
   cd /
   /usr/bin/env -i \
     PATH=/usr/bin:/bin \
     HOME=/absolute/path/to/new-run-release-home \
     TMPDIR=/absolute/path/to/new-run-release-tmp \
     GOCACHE=/absolute/path/to/new-run-go-build-cache \
     GOMODCACHE=/absolute/path/to/verified-read-only-go-module-cache \
     GOWORK=off GOFLAGS=-mod=readonly GOENV=off \
     GO=/absolute/path/to/go1.26.6/bin/go \
     VERSION=v0.2.1-rc-materialized \
     CANDIDATE_SOURCE_DIR=/absolute/path/to/read-only-materialized-candidate \
     CANDIDATE_IDENTITY_LOCK=/absolute/path/to/candidate-identity.lock \
     CANDIDATE_IDENTITY_LOCK_SHA256=<exact-lock-bytes-64-lowercase-hex> \
     /bin/sh /absolute/path/to/read-only-materialized-candidate/scripts/release_preflight.sh
   ```

   Require `release_preflight=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED`,
   `evidence_mode=ITERATION_ONLY`, `final_evidence=false`, and
   `release_approved=false`. A successful exit validates the technical gates
   and lock schema only; it is not final evidence or approval.
10. From the same external driver, read-only candidate, lock, controlled
    directories, and caches on the physical `ssh ceo` host, run:

    ```bash
    cd /
    /usr/bin/env -i \
      PATH=/usr/bin:/bin \
      HOME=/absolute/path/to/new-run-release-home \
      TMPDIR=/absolute/path/to/new-run-release-tmp \
      GOCACHE=/absolute/path/to/new-run-go-build-cache \
      GOMODCACHE=/absolute/path/to/verified-read-only-go-module-cache \
      GOWORK=off GOFLAGS=-mod=readonly GOENV=off \
      GO=/absolute/path/to/go1.26.6/bin/go \
      VERSION=v0.2.1-docker-materialized \
      BUILD_DATE=<utc-build-date> \
      PORT=<free-port> \
      REMOTE_HOST=local \
      CANDIDATE_SOURCE_DIR=/absolute/path/to/read-only-materialized-candidate \
      CANDIDATE_IDENTITY_LOCK=/absolute/path/to/candidate-identity.lock \
      CANDIDATE_IDENTITY_LOCK_SHA256=<exact-lock-bytes-64-lowercase-hex> \
      /bin/sh /absolute/path/to/read-only-materialized-candidate/scripts/ceo_docker_smoke.sh
    ```

    Require `ceo_docker_smoke=SCHEMA_VALIDATED_NOT_RELEASE_APPROVED`,
    `evidence_mode=ITERATION_ONLY`, `final_evidence=false`, and
    `release_approved=false`.
11. On an isolated Linux host, execute the complete legacy-store migration and
    rollback drill below against the frozen candidate and the real `v0.2.0`
    binary: migrate a file-backed legacy store, require strict-v2 health/auth/KMS/
    TLS-provider smoke, restore the complete encrypted backup plus old config,
    then require the same smoke through `v0.2.0`. The runner must execute inside
    a delegated cgroup v2/PID namespace or equivalent supervisor that can prove
    the complete descendant set is empty before PASS; process-group cleanup alone
    is insufficient because a descendant can call `setpgid(2)` or `setsid(2)`.
    Record the candidate SHA and independently manifest-bound SHA-256 of both
    binaries; a dirty or rebuilt candidate makes the drill stale.
12. Independent security, runtime-architecture, and quality reviews of the
    frozen post-merge candidate with no open accepted P0/P1 findings.
13. Require the post-merge `main` GitHub Actions and independent-QA runs to be
    green on the exact `candidate_sha`; a PR synthetic-merge run is not enough.
    The source CI quality job deliberately uses
    `AEGIS_DISPOSABLE_CEO=1` plus `ALLOW_UNVERIFIED_ITERATION=1` and an absolute
    Go path. Its only acceptable preflight terminal is
    `TECHNICAL_ITERATION_PASS` with `evidence_mode=ITERATION_ONLY`,
    `final_evidence=false`, and `release_approved=false`; GitHub-hosted CI does
    not provide external candidate trust or final approval.
14. Create the annotated `v0.2.1` tag locally, without publishing it, targeting
    `candidate_sha`. Finalize the external manifest including that tag object,
    then compute its detached digest.
15. The real independent human approver must review the finalized manifest and
    issue a detached approval binding the manifest digest, `candidate_sha`, and
    the ordered published-artifact digest set. Only after that approval verifies
    against an independently administered trust policy may the release owner
    publish the immutable tag, manifest, and detached attestations through the
    selected evidence surface. A public key, identity, role, or key ID selected
    by the release owner in the same invocation is not a trust anchor.
    `v0.2.0` must not move.

The detached materialized identity lock consumed by gates 9 and 10 has exactly
these 13 ordered fields:

```text
schema=aegis-candidate-materialized-lock-v1
materialization_state=complete
claimed_candidate_sha=<40-lowercase-hex>
claimed_candidate_tree=<40-lowercase-hex>
claimed_worktree_clean=true
claimed_source_archive_sha256=<64-lowercase-hex>
claimed_object_closure_sha256=<64-lowercase-hex>
claimed_materialized_root_sha256=<64-lowercase-hex>
claimed_verifier_sha256=<64-lowercase-hex>
claimed_verifier_provenance_sha256=<64-lowercase-hex>
claimed_materializer_sha256=<64-lowercase-hex>
claimed_materializer_provenance_sha256=<64-lowercase-hex>
claimed_materialized_format=aegis-readonly-source-git-dir-v1
```

The repository validates this schema and binds the exact lock bytes and
read-only directory metadata during a run, but does not establish the external
verifier, materializer, provenance, or claims as trustworthy. Gates 9 and 10
remain `BLOCKED_EXTERNAL` until those inputs are independently produced and
verified; even then their repository terminals remain
`SCHEMA_VALIDATED_NOT_RELEASE_APPROVED`, not final approval.

Before either gate, independently pinned verifier and materializer binaries
must recompute and agree on the source archive digest, complete Git object
closure, candidate SHA/tree, and deterministic materialized-root digest. The
same read-only mount must be rechecked after each gate, and a detached
attestation must bind those values, the exact identity-lock digest, and both
tools' binary and provenance digests. A missing recomputation, mismatch,
changed mount, unbound value, or unavailable detached attestation leaves the
gate `BLOCKED_EXTERNAL`.

The `/usr/bin/env -i` driver, fixed `/bin/sh`, absolute Go binary, and controlled
directories are part of the external trusted computing base. `HOME`, `TMPDIR`,
and `GOCACHE` must be freshly created outside the candidate for each run with
owner-only write access, then destroyed with post-run absence evidence; their
mutable contents are scratch, not stable candidate digests. `GOMODCACHE` must be
independently prefilled and content-verified, then mounted read-only for both
gates. The independently pinned verifier must check the same candidate mount
and deterministic root digest immediately before and after each direct-script
invocation and bind those observations, the verified module-cache digest, the
scratch lifecycle evidence, and the launcher/environment identities into the
detached attestation. Repository Make targets are developer/bootstrap
conveniences only; ambient `MAKEFILES`, `MAKEFLAGS`, or other pre-parse state
must never sit on the trusted Gate 9 or 10 path. Missing launcher provenance,
unsafe directory ownership or permissions, module-cache or mount drift,
scratch residue, or an incomplete binding leaves the gate `BLOCKED_EXTERNAL`.

`AEGIS_DISPOSABLE_CEO=1` and `ALLOW_UNVERIFIED_ITERATION=1` may be used together
only for disposable technical bootstrap runs. Such runs deliberately report
unavailable candidate identities and may emit only `TECHNICAL_ITERATION_PASS`
with `evidence_mode=ITERATION_ONLY`, `final_evidence=false`, and
`release_approved=false`. They cannot be mixed with the three external
materialized-source inputs and cannot satisfy gates 9 or 10. Final artifact
identities must embed the same full 40-character `candidate_sha`; short,
unverified, or bootstrap identities are not final evidence.

Gate 11 uses a caller-supplied prebuilt repository runner and caller-built
inputs; the runner never downloads or builds itself or either Aegis binary:

```bash
GOTOOLCHAIN=go1.26.6 make rollback-drill \
  RUNNER_BIN=/absolute/path/to/verified/aegis-rollback-drill \
  CANDIDATE_BIN=/absolute/path/to/frozen-v0.2.1/aegis \
  ROLLBACK_BIN=/absolute/path/to/verified-v0.2.0/aegis \
  INPUT_LOCK=/absolute/path/to/verified-rollback-input-lock.json \
  INPUT_LOCK_SHA256=<verified-exact-lock-bytes-64-lowercase-hex>
```

The command requires Linux `amd64` or `arm64`, mounted `/proc`, executable
sealed memfds, a clean checkout whose `HEAD` equals the lock-bound full SHA,
candidate build metadata with the same clean VCS revision, exact
`v0.2.1`/`v0.2.0` binary version identities, and bounded regular executable
inputs. The caller must supply an independently generated and verified strict
`aegis.rollback-input-lock/v2` file plus the SHA-256 of its exact bytes. The
lock binds the canonical run ID and containment nonce, candidate commit and
binary digest, fixed `v0.2.0` tag/commit and binary digest, all candidate and
rollback provenance references and digests, the runner binary digest, runner
provenance reference and digest, the independent trust policy URI and digest,
builder identity, and creation time. The runner validates the lock's exact
schema and bindings and derives every candidate/rollback/runner identity and
digest from it; it does not validate the lock's authority or signature, which
remains an independent verifier responsibility.

The prebuilt runner opens the actual Linux `/proc/self/exe`, hashes that opened
inode, validates its Go module/package path plus VCS revision and modified state
against the candidate checkout, compares its SHA-256 to the lock-bound runner
binary digest, keeps that descriptor open, and rehashes it before PASS. The
repository identity check pins the canonical caller-supplied worktree and its
real `.git` directory with no-following descriptors, rejects bare/linked,
promisor/alternate-object, and unsafe-permission layouts, and invokes fixed
`/usr/bin/git` with explicit descriptor-backed `--git-dir`/`--work-tree`, a
minimal environment, replacement objects disabled, and lazy fetch disabled. It
requires SHA-1 object format and parses a strictly bounded raw candidate tree;
an independent no-following worktree walk compares every regular blob,
executable mode, symlink target, missing path, and extra path and produces a
deterministic raw-worktree digest. The result is exact schema-version-3 JSON and
records `run_id`,
`containment_nonce`, canonical UTC `started_at`/`ended_at`,
`runner_binary_sha256`, and `input_lock_digest` alongside the candidate and
rollback identities. These fields prevent report splicing only when an
independent containment attestation binds the same run ID and containment nonce.

The runner opens each Aegis binary path once with symlink refusal, copies the
bytes into an anonymous Linux memfd, applies
`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`, and performs hash,
exact version, Go build-info, execution, and final rehash checks only against
that same sealed object. It also rechecks the repository SHA, clean/dirty state,
and exact raw-worktree digest immediately before emitting evidence.

The repository runner deliberately does not claim to establish trust in its
caller-supplied input lock or to be a sandbox for a hostile binary. Gate 11 must
run with external containment on a disposable dedicated host with no ambient
credentials, no network path except the drill's loopback fixture, a delegated
cgroup/PID-namespace or equivalent whole-process-tree supervisor, and evidence
that no descendant remains after each binary invocation. Without that external
containment and a real Linux execution of the sealed-fd tests plus the complete
drill, Gate 11 is `BLOCKED_EXTERNAL`. An iteration may add
`ROLLBACK_DRILL_FLAGS=--allow-dirty-iteration`; its JSON result is explicitly
`ITERATION_ONLY` and cannot satisfy gate 11.

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
- A running reader detects generation rollback, same-generation content drift,
  and any higher-generation deletion or retention shortening of an unexpired
  tombstone. Restoring an older valid snapshot before restart is outside the
  single-file design's detection boundary; restore procedures must merge the
  union of all unexpired tombstones rather than choosing an older copy.
- The local backend is supported only on a single host and local filesystem.

## Evidence Lifecycle and External Manifest

Tracked documentation may record the release plan, decisions, historical
results, and pre-freeze ledger entries only. It must not be changed after
candidate freeze to embed final exact-SHA CI results or artifact digests: doing
so would create a new candidate SHA and invalidate the evidence it just added.
`docs/review-remediation-2026-07-15.md` therefore remains a historical ledger,
not the final evidence manifest.

After the candidate is frozen, final evidence must be written outside the
candidate Git tree to a content-addressed, write-once or otherwise immutable
evidence manifest. The operator must choose its external location, retention,
access-control, and immutability mechanism before final freeze. The manifest
must contain at least:

- `schema_version`, `release_version`, `created_at`, the full
  `candidate_sha`, `candidate_tree`, `worktree_clean` assertion, `tag_name`,
  annotated `tag_object_sha`, and `tag_target_sha`;
- `artifact_scope.decision` and, for every `artifacts[]` entry, `type`,
  `platform`, immutable `reference`, SHA-256 or native `digest`, embedded
  `source_sha`, and `toolchain`;
- `sbom`, `signature`, and `provenance` identity/status for each published
  artifact; every built artifact requires `present` evidence. The scope-level
  fields use justified `not_applicable` for `source_tag_only`, or the fixed
  `supply-chain evidence is recorded per artifact` marker for a built scope;
  they cannot carry a second, independently mutable attestation identity;
- for every `gates[]` entry, `name`, `status`, `timestamp`, `tool_version`,
  immutable `run_url`/`run_id`, content-addressed `evidence_ref` and
  `evidence_digest`, and the same full `candidate_sha`; artifact tests must also
  bind the ordered `artifact_digests` set, and the SBOM, signature, and
  provenance verification gates must bind the corresponding ordered
  `attestation_references` and `attestation_digests`;
- `qa.repository`, `qa.revision`, `qa.sut_sha`, the actual independently tested
  `qa.sut_binary_digest`, any ordered published-artifact bindings in
  `qa.sut_digests`, `qa.run_url`/`qa.run_id`, `qa.evidence_ref`, and
  `qa.evidence_bundle_digest`;
- Mac Mini/container run/evidence identity, artifact-binding mode,
  SHA-256 `image_id`/`image_digest`, `os`, `architecture`, `runtime_user`,
  `read_only_root`, and health/auth/revocation/cleanup results when containers
  are in scope;
- `reviewers[]` with technical dispositions and a
  `release_approval_policy` naming the required independent-human role, key
  fingerprint, immutable trust-policy URI/digest, and independently operated
  verifier URI/digest, plus migration/restore/rollback evidence bound to an
  independently produced input lock, content-addressed report, and whole-process
  containment proof; `accepted_risks` must include description, mitigation,
  evidence, named acceptance authority/time, owner, and deadline; final
  `open_findings` and `unverified_surfaces` must both be empty; and
- a stable `manifest_id` and `retention_policy`. A detached digest and
  signature/attestation plus the immutable external URI must be published
  alongside the manifest; the manifest must not try to embed its own digest.

All records must bind to the same candidate SHA and, where applicable, the same
artifact digest. At minimum, `tag_target_sha == candidate_sha`, every
`artifacts[].source_sha` and every `gates[].candidate_sha` must equal
`candidate_sha`, and `qa.sut_sha == candidate_sha`; when a gate or QA run tests
an artifact, its recorded digest must equal the digest of the artifact that
will be published. A candidate-tree change, artifact rebuild, mutable evidence
replacement, dirty/override run, or mismatched SHA makes the affected record
`STALE` and requires the relevant final gates and manifest to be regenerated.
The independent human approval is a separate detached object, not a manifest
field. It must contain approver identity and role, decision, timestamp,
`manifest_digest`, `candidate_sha`, and the ordered `artifact_digests`; all must
match the finalized manifest. A manifest, candidate, tag, or artifact change
invalidates that approval and requires a new one. Bootstrap-owner assent,
technical or agent review, and protected-PR merge approval are not substitutes
for this final release approval.

Run `make release-manifest-schema RELEASE_MANIFEST=/absolute/path/manifest.json`
to validate the repository-owned schema, exact-SHA/digest relationships,
required gates, JSON ambiguity/complexity bounds, fixed `v0.2.0` rollback
identity, and the requirement that final `open_findings` and
`unverified_surfaces` are empty. Success prints
`SCHEMA_VALID_NOT_RELEASE_APPROVED`; it is not a release authorization. The
repository tool deliberately returns non-zero even when a caller-supplied
Ed25519 signature is internally valid, because the same caller can also select
that public key and claimed identity. Final approval verification remains
`BLOCKED_EXTERNAL` until an independent administrator provisions an immutable
trust policy mapping the approver identity/role to a pinned Ed25519 public-key
fingerprint (`key_id = sha256(raw_public_key)`) outside the release owner's
control. That external verifier and policy URI/digest must be recorded in the
manifest evidence set before Gate 15 can pass.

The manifest must not contain secrets, prompts, completions, authorization
headers, or raw sensitive logs.

## Post-publication Closure

Publication is not the end of the release window. From an independent clean
environment, fetch the remote annotated tag and immutable evidence objects;
verify the tag object and target, manifest digest, detached human approval,
trust-policy fingerprint, ordered artifact digests, and every required
signature/SBOM/provenance binding. For a built-artifact scope, run the selected
published artifact's health/auth/revocation/provider smoke without rebuilding
it. For `source_tag_only`, verify the fetched tag/tree/archive identities and
do not pretend that a locally rebuilt executable is a published artifact. Keep the
rollback owner on call and monitor startup failures, authentication/revocation
errors, provider failures, saturation, and abnormal exits for the scheduled
rollback window. Any identity mismatch or critical smoke/monitoring failure
invokes abort authority and the documented restore-before-v0.2.0 rollback; it
must not be relabeled as a successful release.

Record that result outside the candidate tree as
`aegis.release-closure/v1`. It binds the exact manifest and detached approval,
trust-policy and verifier digests, candidate/tag/artifact tuple, remote
verification, scope-aware published smoke, monitoring window, and either a
`RELEASED` or `ROLLED_BACK` outcome with content-addressed evidence. Validate
the record without granting authority:

```bash
make release-closure-schema \
  RELEASE_MANIFEST=/absolute/path/to/final-manifest.json \
  RELEASE_CLOSURE=/absolute/path/to/release-closure.json
```

Success prints `CLOSURE_SCHEMA_VALID_NOT_RELEASE_APPROVED`; the independently
administered verifier remains the authority for approval and closure policy.
