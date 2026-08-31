# Aegis

**Security-first LLM API Gateway**

Aegis is a lightweight, secure gateway for managing access to multiple LLM providers. It provides unified API access, encrypted key management, intelligent routing, request/token rate limiting, and optional in-memory budget control through a single binary.

## Why Aegis?

| Problem | Aegis Solution |
| :--- | :--- |
| API keys scattered across services | Centralized KMS with AES-256-GCM encryption |
| No visibility into LLM costs | Cost tracking architecture and planned quota enforcement |
| Single provider dependency | Provider routing framework with OpenAI-compatible baseline |
| Rate limit errors from providers | In-memory request/concurrency limiter baseline |
| PII leakage to third-party APIs | Built-in PII detection and redaction |
| Supply chain attack risk | Go static binary, Distroless image, zero runtime deps |

## Architecture

Aegis uses a **microkernel + middleware pipeline** architecture:

```
Request → [Auth] → [RateLimit] → [Quota?] → [PII] → [Router] → [KMS] → [Adapter] → [Proxy] → Provider
```

Every feature is a middleware plugin. The core is minimal and auditable.

## Current Implementation Status

Architecture truth surface: `v0.2.1`, superseding the `v0.2.0` hardening baseline.

This repository currently provides the runtime framework and a minimal OpenAI-compatible gateway path:

- Implemented baseline: safe logger, strict config loading, fail-closed middleware composition, HS256 virtual-key issuance/validation (including budget and per-key TPM claims), durable single-host revocation, in-memory RPM/TPM/concurrency limiting, optional in-memory quota, PII redaction, in-request failover, weighted same-priority routing, keyID-bound local encrypted file KMS, an offline Operator CLI, loopback Admin issue/revoke/usage, egress allowlist validation, adapters for OpenAI/DeepSeek/OpenRouter/Azure/Anthropic/Gemini, and streaming response proxying.
- Explicitly not production-ready yet: BYOK key-source runtime, Vault KMS, Redis rate limiter, durable quota/control-plane store, and a public (non-loopback) Admin UI.
- Fail-fast behavior: unknown config fields, empty auth issuer, a missing durable local KMS path, enabled providers without a canonical non-empty model set, missing/unreadable enabled-provider credentials, disabled request limiting, missing/unsupported JWT key source, unsupported Vault/Redis/store capabilities, quota enabled without model prices, Admin bound off loopback, and an exhausted pipeline without a terminal response are rejected instead of silently running without controls.

## Dedicated Test-Server Smoke

Run smoke tests only on the dedicated `ssh ceo` test server (or its controlled
Linux container), with an absolute Go 1.26.6 binary path. The bootstrap mode
below is explicitly unverified iteration feedback, not release evidence or
release approval. On that server, create fresh owner-only home, temporary, and
Go build-cache directories for the run; use an independently prefilled,
verified, read-only Go module cache; then launch from outside the candidate
through a sterile environment:

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
  /bin/sh /absolute/path/to/candidate/scripts/local_smoke.sh
```

Its terminal must be `local_smoke=TECHNICAL_ITERATION_PASS` with
`evidence_mode=ITERATION_ONLY`, `final_evidence=false`, and
`release_approved=false`. Destroy the three per-run scratch directories after
the run and verify they no longer exist; do not treat their mutable contents as
candidate evidence.

For manual smoke testing on that same dedicated server:

```bash
# Generate a 256-bit master key for local KMS
export AEGIS_MASTER_KEY=$(openssl rand -hex 32)
export AEGIS_JWT_KEY=$(openssl rand -hex 64)

# Build, initialize durable revocation state, import one provider key from
# bounded non-terminal stdin, and issue a virtual key into a new 0600 file.
make build \
  GO=/absolute/path/to/go1.26.6/bin/go \
  VERSION=v0.2.1-rc-iteration \
  COMMIT=iteration-bootstrap-unverified \
  BUILD_DATE=<utc-build-date>
./bin/aegis operator revocation init --config aegis.example.json
printf '%s' "$OPENAI_API_KEY" | ./bin/aegis operator provider-key import \
  --config aegis.example.json --provider openai-primary
./bin/aegis operator virtual-key issue \
  --config aegis.example.json \
  --subject local-client \
  --models gpt-4o-mini \
  --ttl 1h \
  --out ./local-client.jwt

# Run Aegis in one terminal.
./bin/aegis --config aegis.example.json

# Verify the process is alive from another terminal
curl http://localhost:8080/health
```

The Operator CLI is a standalone/offline management path, not a network Control Plane. OpenAI-compatible clients can use the issued JWT as their API key:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key=open("local-client.jwt", encoding="utf-8").read().strip()
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
    stream=True
)
print([m.id for m in client.models.list().data])
```

New stores use `kms.local.minimum_envelope_version=2`. To migrate an older
nil-AAD store, stop all KMS writers, temporarily set the field to `1`, run
`operator kms migrate --dry-run`, then `--apply --backup-dir <new-dir>`. Require
a second dry-run to report `legacy=0`, restore the field to `2`, and restart.
Retain the encrypted backup for rollback. Do not run provider-key imports or
other KMS writers during apply, even though current operator commands share a
local kernel lock. A rollback to v0.2.0 must also restore the complete
pre-v0.2.1 config and its matching auth/storage state. The older binary does
not implement v0.2.1-only semantics such as `minimum_envelope_version` and
`auth.revocation`; silently ignored fields are not a supported mixed-version
rollback.

## Capability Status

| Capability | Status |
| :--- | :--- |
| OpenAI-compatible `POST /v1/chat/completions` path | Implemented; SSE and non-stream |
| `GET /v1/models` | Authenticated catalog intersection of virtual-key models and enabled providers |
| Virtual key auth | Offline HS256 issuance and runtime validation implemented; RS256 is planned |
| Provider support | `openai`, `deepseek`, `openrouter` (OpenAI-compatible), `azure`, `anthropic`, `google` |
| KMS | Local AES-GCM v2 envelope binds ciphertext to key ID as AAD; binary-loaded config requires an encrypted file store; the in-memory backend is limited to explicit programmatic tests; compatibility migration ends in a strict-v2 format floor; Vault is planned |
| Revocation | Versioned local snapshot, serialized atomic CLI/Admin writes, 500 ms polling, in-memory request checks, and within-process monotonic preservation of unexpired tombstones implemented for single-host deployments; cross-restart trusted anchoring and a shared backend are planned |
| Operator CLI | Offline revocation initialization, provider-key import, virtual-key issue/revoke (`--rpm`, `--tpm`, `--budget`), and KMS migration implemented |
| Rate limiting | In-memory per-virtual-key RPM, optional TPM (0 = unlimited), and concurrency implemented and mandatory in v0.2.1; `enabled=false`, zero `default_rpm`, and zero `default_max_concurrency` fail fast; positive defaults are per-key policy ceilings, not aggregate process/IP limits; Redis backend and `redis_url` fail fast until implemented |
| PII protection | Bounded semantic-JSON redaction for the supported OpenAI-compatible schema; escaped strings, duplicate/ambiguous members, PII in keys or numeric positions, and PII split across text parts in one message fail closed or are redacted according to mode. This is lexical DLP, not a guarantee against model-level inference |
| Request memory | The validated transport/semantic request ceiling is 4 MiB; PII additionally enforces a 512 KiB string/joined-text ceiling, 1 MiB content-array ceiling, and structural budgets. Superseded/final byte buffers are zeroed where owned; provider responses are streamed |
| Cost management | In-memory quota when `quota.enabled=true`; JWT/config budget fail-closed; unknown models have no silent default price; durable `quota.dsn` remains reserved |
| Admin API / BYOK | Loopback Admin issues/revokes pool keys and reports usage; BYOK routes stay `501`; `key_source="byok"` virtual keys are rejected until owner/provider binding exists |
| Streaming proxy | SSE forwarding with in-request failover for non-stream 429/5xx/transport; token counting is heuristic then TPM-reconciled |
| mTLS | Server TLS implemented; mTLS requires `ca_file`; `min_version` is currently fixed to TLS 1.3 |

## Deployment Modes

| Mode | Dependencies | Use Case |
| :--- | :--- | :--- |
| **Framework Smoke** | Explicit programmatic test injection + in-memory KMS | Development validation only |
| **Standalone** | Local env vars + encrypted file KMS store | Development and small-team validation |
| **Cluster** | Redis + Vault + durable quota store | Planned |

## Docker Runtime Contract

The image includes `/etc/aegis/aegis.json` derived from `aegis.example.json`, with KMS and revocation state under `/var/lib/aegis`. Initialize the volume once with the same release binary before starting the gateway:

```bash
make docker VERSION=v0.2.1-rc-local

# Generate once for this isolated smoke session. Docker inherits the values;
# the secrets are not expanded into its command-line arguments.
export AEGIS_MASTER_KEY
export AEGIS_JWT_KEY
AEGIS_MASTER_KEY="$(openssl rand -hex 32)"
AEGIS_JWT_KEY="$(openssl rand -hex 64)"

docker volume create aegis-data
docker run --rm \
  -e AEGIS_MASTER_KEY \
  -e AEGIS_JWT_KEY \
  -v aegis-data:/var/lib/aegis \
  aegis:v0.2.1-rc-local \
  operator revocation init --config /etc/aegis/aegis.json

docker run --rm \
  --read-only \
  -e AEGIS_MASTER_KEY \
  -e AEGIS_JWT_KEY \
  -v aegis-data:/var/lib/aegis \
  -p 8080:8080 \
  aegis:v0.2.1-rc-local
```

The bundled example config is non-secret and suitable only for smoke validation. The shell variables above are ephemeral smoke credentials: keep them for every command that reuses the volume, or destroy the smoke volume before generating replacements. Never use this command as a deployment secret store; inject stable values from an approved secret manager. Any binary-loaded config must provide `kms.local.key_store_path`; put it and `auth.revocation.file_path` on durable local storage. Import every enabled provider key before starting the gateway: startup decrypts each distinct configured `api_key_id` and fails closed if any credential is absent, corrupt, or empty. Local revocation files are not a multi-host store and cannot detect restoration of an older valid snapshot before restart; recovery must preserve the union of unexpired tombstones.

The default Docker target tags only the explicit `VERSION`. Set `DOCKER_TAG_LATEST=true` only for a supported release.

## Security

Security is Aegis's highest priority. See [SECURITY.md](SECURITY.md) for:
- Vulnerability reporting process
- Security design principles
- Secure development guidelines

**Key security properties:**
- API keys never exist in plaintext at rest
- Memory is zeroed after credential use
- Egress filtering binds configured provider requests to allowlisted HTTPS host/port endpoints; host-only and `*.` rules mean port 443, non-default ports require exact entries, DNS answers fail closed if any address is non-public, and IP literals require an explicit exact IP+port rule
- Unknown JSON configuration fields, an empty auth issuer, and a missing JWT `key_source` fail closed
- Encoded virtual keys are limited to 16 KiB and HTTP headers to 64 KiB before signature work; semantic request processing is capped separately as documented above
- No shell or package manager in production image

## Project Structure

```
cmd/aegis/          → Application entry point
internal/
  config/           → Configuration loading and validation
  server/           → HTTP server and middleware pipeline
  middleware/       → Auth, rate limit, PII, router, KMS, adapter
  kms/              → Key management (local AES implemented; Vault reserved)
  operator/         → Privileged offline use-case coordination
  revocation/       → Durable single-host revocation snapshot
  virtualkey/       → Shared token issuance and validation contract
  proxy/            → Streaming proxy engine
  quota/            → Budget and cost management
  model/            → OpenAI-compatible API types
  utils/            → Memory zeroing, safe logging
```

## Contributing

Contributions are welcome. Please read [SECURITY.md](SECURITY.md) for security guidelines before submitting code.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Release Plan

See [docs/release-plan-v0.2.1.md](docs/release-plan-v0.2.1.md) for the current
`v0.2.1` go/no-go gates and release ownership checklist.

## License

MIT License. See [LICENSE](LICENSE).
