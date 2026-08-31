# AegisLLM Architecture Remediation Review

## Version

| Field | Value |
| --- | --- |
| Review version | `v0.2.1` |
| Supersedes | `v0.1.0` pre-remediation architecture review |
| Baseline reviewed | `v0.1.0` exposed planned/scaffolded capabilities without consistent fail-fast truth |
| Remediated baseline | `v0.2.1` adds a supported offline operator path, keyID-bound KMS format, and durable single-host revocation |

## Result

The previous architecture review found several Redis-like gaps where documents, config fields, or interfaces exposed capabilities that runtime did not enforce. This remediation converts the highest-risk gaps into explicit fail-fast behavior and aligns the public truth surface.

The deeper 2026-07-15 follow-up, evidence reconciliation, prioritized task board, and product-decision queue are maintained in `docs/review-remediation-2026-07-15.md`.

## Fixed In This Slice

| Area | Remediation |
| --- | --- |
| Quota / budget | Default and example config disable quota; `quota.enabled=true` is rejected until runtime enforcement exists |
| TPM | Default and example TPM values are zero; provider `max_tpm`, `rate_limit.default_tpm`, and JWT `tpm` fail closed |
| Redis | Redis remains reserved and fails fast during config/runtime validation |
| Vault | Vault remains reserved and fails fast during config/runtime validation; docs now say reserved, not implemented |
| Admin / BYOK | Docs now state the handler scaffold is not mounted by the main gateway, and `key_source="byok"` fails closed until owner/provider binding exists |
| Provider adapters | Docs and comments now state only OpenAI-compatible OpenAI/DeepSeek are current runtime paths |
| Docker | Image includes non-secret example config and a nonroot-owned `/var/lib/aegis`; README documents required mounts |
| Stale docs | Root architecture/review documents replaced with current runtime truth |

## Remaining Planned Work

- Implement quota middleware and a durable quota store.
- Implement TPM preflight reservation and post-response reconciliation.
- Replace local revocation with a reviewed shared backend before multi-host deployment.
- Implement Vault KMS client with failure-mode tests.
- Mount Admin API only after issuance, BYOK storage, revocation, and audit are delivered atomically.
- Add real Anthropic/Gemini adapter contract tests before enabling those provider types.

## Acceptance Evidence

Run on the dedicated `ssh ceo` test server before claiming technical
remediation complete:

```bash
cd /
/usr/bin/env -i \
  PATH=/usr/bin:/bin \
  HOME=/absolute/path/to/new-run-home \
  TMPDIR=/absolute/path/to/new-run-tmp \
  GOCACHE=/absolute/path/to/new-run-go-build-cache \
  GOMODCACHE=/absolute/path/to/verified-read-only-go-module-cache \
  GOWORK=off GOFLAGS=-mod=readonly GOENV=off \
  AEGIS_DISPOSABLE_CEO=1 ALLOW_UNVERIFIED_ITERATION=1 \
  GO=/absolute/path/to/go1.26.6/bin/go \
  VERSION=v0.2.1-rc-iteration \
  /bin/sh /absolute/path/to/candidate/scripts/release_preflight.sh
/usr/bin/env -i \
  PATH=/usr/bin:/bin \
  HOME=/absolute/path/to/new-run-home \
  TMPDIR=/absolute/path/to/new-run-tmp \
  GOCACHE=/absolute/path/to/new-run-go-build-cache \
  GOMODCACHE=/absolute/path/to/verified-read-only-go-module-cache \
  GOWORK=off GOFLAGS=-mod=readonly GOENV=off \
  AEGIS_DISPOSABLE_CEO=1 ALLOW_UNVERIFIED_ITERATION=1 \
  REMOTE_HOST=local \
  GO=/absolute/path/to/go1.26.6/bin/go \
  VERSION=v0.2.1-docker-iteration \
  BUILD_DATE=<utc-build-date> \
  PORT=<free-port> \
  /bin/sh /absolute/path/to/candidate/scripts/ceo_docker_smoke.sh
```

These bootstrap calls may emit only `TECHNICAL_ITERATION_PASS` with
`evidence_mode=ITERATION_ONLY`, `final_evidence=false`, and
`release_approved=false`. They do not establish candidate identity, external
trust, final evidence, or release approval. The external materialized-source
path is defined in `docs/release-plan-v0.2.1.md` and is itself only schema
validated until independent verification and approval are complete.
The sterile launcher, absolute tool paths, controlled directories, and cache
contents are part of the external test environment's trust boundary; repository
Make targets are convenience wrappers, not trusted release launchers.
Create `HOME`, `TMPDIR`, and `GOCACHE` fresh with owner-only write access for
each run, then destroy them and verify absence. Prefill, independently verify,
and mount `GOMODCACHE` read-only; it is the cache whose content identity is
bound, while the three scratch directories are bound by lifecycle evidence.

Do not claim a supported release until the branch is pushed, GitHub Actions are
green on the final SHA, ownership is assigned in `docs/release-plan-v0.2.1.md`,
the external materialized-source gates and detached independent approval are
complete, and the `v0.2.1` tag is created.
