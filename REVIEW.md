# AegisLLM Architecture Remediation Review

## Version

| Field | Value |
| --- | --- |
| Review version | `v0.2.0` |
| Supersedes | `v0.1.0` pre-remediation architecture review |
| Baseline reviewed | `v0.1.0` exposed planned/scaffolded capabilities without consistent fail-fast truth |
| Remediated baseline | `v0.2.0` aligns config, runtime guardrails, and documentation truth surface |

## Result

The previous architecture review found several Redis-like gaps where documents, config fields, or interfaces exposed capabilities that runtime did not enforce. This remediation converts the highest-risk gaps into explicit fail-fast behavior and aligns the public truth surface.

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
- Promote revocation store into a managed runtime dependency and connect admin revocation.
- Implement Vault KMS client with failure-mode tests.
- Mount Admin API only after issuance, BYOK storage, revocation, and audit are delivered atomically.
- Add real Anthropic/Gemini adapter contract tests before enabling those provider types.

## Acceptance Evidence

Run before claiming local remediation complete:

```bash
make release-preflight GO=$HOME/.cache/codex-go/go1.26.4/bin/go VERSION=v0.2.0-rc-local
make ceo-docker-smoke VERSION=v0.2.0-docker-test COMMIT=<candidate-sha> BUILD_DATE=<utc-build-date> PORT=<free-port>
```

Do not claim a supported release until the branch is pushed, GitHub Actions are
green on the final SHA, ownership is assigned in `docs/release-plan-v0.2.0.md`,
and the `v0.2.0` tag is created.
