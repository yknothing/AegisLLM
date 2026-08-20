# Independent QA Baseline

AegisLLM uses two different test authorities:

- Source-repository `*_test.go` files are developer-owned white-box regression tests.
- `yknothing/AegisLLM-QA` is an independently versioned, binary-only black-box acceptance suite.

The independent result is valid only for the tuple recorded in `report-v1.json`: the actual tested checkout SHA, optional PR head/base provenance, QA commit, SUT SHA-256, clean Go build information, workflow run identity, and Linux network-isolation environment.

## Merge protocol

1. A QA baseline change is reviewed and merged in `AegisLLM-QA` first.
2. A separate source PR changes `qa-baseline.lock` to that protected-main commit.
3. After bootstrap, a lock PR may change no other file.
4. Source CI builds Aegis once with `GOWORK=off GOFLAGS=-mod=readonly`, verifies the candidate HEAD/tree and clean status both before and after that build, verifies the QA commit is an ancestor of QA `main`, and runs both artifacts in a read-only `--init --network none --pids-limit 64` container. The source workflow supplies a fixed `FROM scratch` image manifest containing only the two prebuilt binaries and requires it to match the QA repository's governed `Dockerfile.runner` byte-for-byte; neither side can add a build stage or rebuild the SUT unilaterally.
5. `Independent QA baseline` is a required source-repository status check.

Never pin a branch, tag, short SHA, fork, or QA commit that is not an ancestor of protected QA `main`. Never use `pull_request_target` to execute candidate code.

## Evidence semantics

The required lane is Linux-only because the current Aegis binary has no outbound CA configuration and macOS does not honor `SSL_CERT_FILE` for system roots. macOS runs QA framework unit tests; it is not an exact-artifact black-box pass.

The workflow binds the actual checked-out SHA (`git rev-parse HEAD`) separately from PR head/base provenance and requires it to equal `github.sha`. It hashes the host SUT before and after execution and verifies that the image contains the same bytes. The runner verifies `debug/buildinfo` VCS data and `--version`, and then a separate read-only `verify` invocation recomputes identity from external expectations. Before upload, the host requires a bounded owner-only regular report, verifies that its bytes did not change, and copies only that exact `report-v1.json` into a non-mounted upload directory. Evidence contains result codes and hashes only—never raw prompts, completions, tokens, keys, headers, subprocess logs, or captured traffic.

A missing report, output overflow, required `not_run`, changed artifact, build-info mismatch, canary finding, or verifier mismatch fails the gate. Vulnerability database unavailability is `not_run`, not a vulnerability-free result.

## Test data and incident handling

Only per-run synthetic canaries are allowed. Production credentials, configs, data, provider endpoints, proxies, and DNS must not enter the QA environment. P0 cases cannot be skipped or waived. A P1/P2 quarantine requires an issue, owner, reason, and expiry within seven days, and never converts a required release gate to pass.

Do not upload raw gateway logs or the temporary workspace. If a canary leak is found, retain only the canary label, surface classification, count, and immutable revision tuple.

## Ownership status

`@yknothing` is currently the bootstrap repository governance owner. That is not an independent human QA identity. The technical repository/module/history boundary and no-bypass rules can be installed now, but independent-human ownership is complete only after a real QA engineer or QA team is granted the intended repository role, added to CODEOWNERS, and shown by a protected review. Until then this remains an explicit governance gap.

## Final release approval contract

Protected-PR review and final release approval are separate decisions. A merge
approval does not automatically approve the later release evidence.

After the candidate tree, artifacts, local/Mac Mini/Linux gates, exact-SHA CI,
and QA evidence are frozen, the release owner finalizes the external manifest
and computes its detached digest. A real independent human QA/release approver
must then issue a detached approval that contains:

- approver identity, repository/team role, decision, and timestamp;
- the finalized `manifest_digest` and full `candidate_sha`; and
- the ordered `artifact_digests` set, including an explicit empty set when the
  approved artifact scope is source tag only.

The approver must be independent of candidate authorship and the last push and
must hold the documented QA/release role. The bootstrap administrator,
technical or agent reviewer, automation identity, and candidate author/last
pusher do not satisfy this gate. Any manifest, candidate, tag, or artifact
change invalidates the approval. The approval remains outside the manifest so
it can sign the finalized manifest digest without creating a self-reference.

## Local verification

Framework unit tests are portable:

```bash
cd /path/to/AegisLLM-QA
GOWORK=off GOFLAGS=-mod=readonly go test -race -shuffle=on -count=3 ./...
go vet ./...
```

The exact-artifact baseline must run through the Linux scratch runner with external network disabled. Do not treat a direct macOS invocation as equivalent.
