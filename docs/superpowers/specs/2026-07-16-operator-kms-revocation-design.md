# AegisLLM v0.2.1 Operator, KMS AAD, and Local Revocation Design

## Status

Approved for implementation. The operator approved the standalone CLI, local
revocation first, and the `v0.2.1` release line. Three independent reviewers
were assigned to attack the KMS, CLI, and revocation decisions before code.

## Goals

1. Make the supported standalone gateway reachable without an unpublished
   out-of-band key seeder or token generator.
2. Bind every newly written local-KMS ciphertext to its key ID without making
   legacy stores unreadable.
3. Make virtual-key revocation durable and visible to a running single-host
   gateway within a documented time bound.
4. Preserve a narrow data plane. No privileged operation is mounted on `/v1`.

## Non-goals

- A network control plane or mounted Admin API.
- BYOK, Vault, Redis, quota, TPM, RS256, or multi-host revocation.
- NFS/SMB as a local revocation backend.
- Automatic rollback to a pre-v0.2.1 binary after v2 KMS writes.

## Decision 1: Offline Operator CLI

### Purpose

The binary currently validates provider keys and virtual tokens but cannot
provision either. A first-class offline CLI closes that operational gap while
keeping privileged mutation outside the public HTTP trust boundary.

### Options

| Option | Benefits | Costs and risks | Verdict |
| --- | --- | --- | --- |
| Keep external scripts | No new code | No supported contract, inconsistent secret handling, Quick Start remains incomplete | Reject |
| Mount a network Control Plane | Central management and future multi-instance path | New listener, authentication, audit, availability, and remote attack surface | Defer |
| Add an offline Operator CLI | Same release binary and config; no network trust boundary; smallest auditable slice | Local filesystem access and single-writer discipline are operator responsibilities | Implement |

### Command contract

The existing server invocation remains compatible. Privileged commands live
under `aegis operator`:

```text
aegis operator revocation init --config <path>
aegis operator provider-key import --config <path> --provider <provider-id> [--replace]
aegis operator virtual-key issue --config <path> --subject <id> --models <csv> [limits] (--out <new-file>|--stdout)
aegis operator virtual-key revoke --config <path> --kid <virtual-key-id>
aegis operator kms migrate --config <path> (--dry-run|--apply --backup-dir <new-empty-dir>)
```

Provider-key plaintext is read from bounded non-TTY `stdin`, never argv or
config, and is zeroed on every exit path. The provider ID must resolve to an
enabled configured provider and its `api_key_id`; the CLI does not accept an
arbitrary KMS key ID. Existing keys require explicit `--replace`. Issued JWTs
are written only after an explicit choice: recommended `--out` creates a new
`0600` file with exclusive-create semantics, while `--stdout` emits only the
token. All status metadata goes to `stderr`. No command logs a provider key,
JWT, request body, or response body. Structural IDs such as `kid` may be argv
values.

`cmd/aegis` owns parsing and process I/O. `internal/operator` owns privileged
use cases. `internal/kms/factory` supplies the same reviewed concrete KMS
construction to server runtime and CLI, preventing configuration drift. The
operator package depends on KMS, virtual-key, and revocation contracts; it does
not depend on the HTTP server or mount an admin handler.

## Decision 2: Versioned KMS Envelope with keyID AAD

### Why the apparent third option is better

It is not a third encryption primitive. AES-256-GCM remains unchanged. The
third option combines the desired keyID AAD with a versioned storage and
migration protocol. Directly switching from nil AAD to keyID AAD would make
every existing blob unreadable and would not give the reader an unambiguous
format discriminator.

### Options

| Option | Benefits | Costs and risks | Verdict |
| --- | --- | --- | --- |
| Keep legacy `nonce || ciphertext`, nil AAD | No migration | Encrypted blobs can be swapped between key IDs | Reject |
| Directly switch to keyID AAD | Stops swaps for new data | Existing blobs immediately fail; format cannot be distinguished safely | Reject |
| Versioned envelope, bounded dual-read migration window, single-write v2, then strict-v2 | Stops v2 swaps; migration remains possible; restored legacy blobs fail after cutover | More format/config code; old binaries cannot read v2 writes | Implement |

### v2 format and authentication

The v2 blob is:

```text
magic || version || nonce_length || nonce || ciphertext_and_gcm_tag
```

AAD concatenates a fixed Aegis local-KMS domain, the fixed-size complete public
envelope header, and the exact key ID as the remaining bounded field. New
writes are v2. Reads accept the legacy raw format only while
`minimum_envelope_version=1`. If a blob begins with the v2 magic, any
invalid/unknown header or GCM failure is terminal; the reader must never retry
it as legacy nil-AAD data. After migration verifies `legacy=0`, deployments set
the minimum to `2`, which rejects any restored legacy blob.

Consequences:

- Moving a v2 blob to another key ID fails GCM authentication.
- Removing the header does not downgrade it: the tag was created with v2 AAD.
- Legacy blobs remain vulnerable to swaps until explicitly migrated.
- Rolling back to an older binary requires restoring the pre-migration backup
  and loses any v2-only writes made after that backup.

### Migration

`operator kms migrate` requires a newly created backup directory. It copies
the encrypted source blobs before rewriting any legacy entry, then rewrites
legacy entries through the normal decrypt/zero/re-encrypt path. Migration is
idempotent and never rewrites a valid v2 entry. Each key-file replacement is
atomic; the operation takes the shared local operator lock, still requires all
older/custom KMS writers to be stopped, and reports partial failure without
deleting the backup. The final dry-run must report `legacy=0` before strict-v2
mode is enabled.

## Decision 3: Durable Single-host Revocation

### Purpose

JWT validation is stateless, so early termination requires durable negative
state. The current process-local map is lost on restart and cannot be updated
by a separate CLI.

### Options

| Option | Benefits | Costs and risks | Verdict |
| --- | --- | --- | --- |
| Process memory only | Fast request path | Restart loss; CLI cannot update it | Test-only |
| Snapshot loaded only at startup | Durable and simple | Every revoke requires a gateway restart | Reject |
| Snapshot read on every request | Near-immediate visibility | Adds disk and parsing to Auth; local filesystem pressure becomes a request-path DoS vector | Reject |
| Append-only log | Natural history and tailing | Framing, torn-tail recovery, compaction, replay, and writer locking expand v0.2.1 | Defer |
| Atomic snapshot + poller + immutable in-memory view | Durable, bounded visibility, O(1) request checks, clean future backend seam | Requires strict corruption and lifecycle handling | Implement |

### Snapshot contract

The strict JSON snapshot contains `version`, monotonic `generation`,
`updated_at`, and entries with `issuer`, `kid`, `revoked_at`, and
`retain_until`. It never stores a complete JWT or client claims. `(issuer,
kid)` is the identity, and `kid` must not be reused.

The CLI writer takes a local kernel advisory lock, reads and validates the
current generation, merges and prunes entries, writes a same-directory `0600`
temporary file, calls `fsync`, atomically renames, and syncs the parent
directory. Concurrent writers serialize; duplicate revoke is idempotent and
never shortens retention.

Retention is `revoke_time + auth.token_expiry + clock_skew`. A caller cannot
request a shorter interval. Manual unrevoke is intentionally unsupported.

The gateway must start from an initialized valid snapshot. A 500 ms poller
strictly reads a bounded snapshot and atomically swaps an immutable map. The
data plane performs no file I/O. A successful CLI commit is visible no later
than `refresh_interval + 250ms`; it does not claim that a gateway has already
observed the new generation.

Missing, deleted, symlinked, non-regular, oversized, weak-permission,
malformed, duplicate, or unknown-version state fails closed. A running reader
also rejects a lower generation or same-generation content change. At startup,
invalid state prevents the server from starting. At runtime Auth returns a
generic `503` for otherwise valid tokens until valid state at least as new as
the reader's last accepted generation is observed. A valid older snapshot
restored before restart cannot be detected without an independent trusted
monotonic anchor; recovery must preserve the union of unexpired tombstones.
Invalid, expired, and revoked tokens remain generic `401` responses.

### Long-term multi-instance exit

The Auth dependency is an error-returning checker keyed by `(issuer, kid)`.
The local file reader and writer stay behind that seam. A future shared backend
must be a reviewed Redis/SQL/control-plane design; shared files are not a
cluster store. Migration uses fail-closed union/dual-read until all active
tombstones and writers have moved.

## Acceptance Contract

- CLI parsing tests prove secrets never need argv and provider-key input is
  bounded and zeroed.
- A CLI-issued token passes the same validator used by Auth; reserved claims
  still fail closed.
- KMS tests cover v2 round-trip, legacy read, blob swap, header strip,
  malformed/unknown version, migration backup, idempotence, and plaintext
  zeroing.
- Revocation tests cover initialization, permissions, atomic update, concurrent
  union, idempotence, retention, restart, polling SLA, deletion/corruption
  degradation, recovery, rollback generation, and race safety.
- A runtime E2E proves valid request -> CLI revoke -> `401` within SLA while a
  second token remains accepted.
- Local release gates and the Mac Mini Docker smoke run against the final
  candidate and exercise initialization, valid authentication, CLI revocation,
  and rejection within the published visibility bound.

## Rollback

Before release/tag, rollback is source-only. After KMS v2 writes, an older
binary is not storage-compatible. Operational rollback therefore requires:

1. stop the gateway and all operator writers;
2. restore the encrypted pre-migration KMS backup;
3. restore the complete pre-v0.2.1 config; do not rely on the older binary
   silently ignoring v0.2.1-only semantics such as
   `kms.local.minimum_envelope_version` and `auth.revocation`;
4. restore the matching pre-v0.2.1 auth/storage state required by that config;
5. deploy the older binary;
6. verify health, auth rejection, and a real provider success path.
