# Aegis

**Security-first LLM API Gateway**

Aegis is a lightweight, secure gateway for managing access to multiple LLM providers. It provides unified API access, encrypted key management, intelligent routing, and request/concurrency rate limiting through a single binary. Cost control is an explicit planned capability and is not enforced in the current runtime.

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
Request → [Auth] → [RateLimit] → [PII] → [Router] → [KMS] → [Adapter] → [Proxy] → Provider
```

Every feature is a middleware plugin. The core is minimal and auditable.

## Current Implementation Status

Architecture truth surface: `v0.2.1`, superseding the `v0.2.0` hardening baseline.

This repository currently provides the runtime framework and a minimal OpenAI-compatible gateway path:

- Implemented baseline: safe logger, strict config loading, fail-closed middleware composition, HS256 virtual-key issuance/validation, durable single-host revocation, in-memory rate limiting, PII redaction, provider routing, keyID-bound local encrypted file KMS, an offline Operator CLI, egress allowlist validation, and streaming response proxying.
- Explicitly not production-ready yet: Admin API key issuance, BYOK key-source runtime, Vault KMS, Redis rate limiter, quota/TPM enforcement, durable control-plane store, and non-OpenAI protocol transformations.
- Fail-fast behavior: unknown config fields, empty auth issuer, missing/unsupported JWT key source, unsupported Vault/Redis/quota/store/TPM capabilities, and an exhausted pipeline without a terminal response are rejected instead of silently running without controls.

## Development Smoke

```bash
GOTOOLCHAIN=go1.26.5 make local-smoke VERSION=v0.2.1-rc-local
```

For manual smoke testing:

```bash
# Generate a 256-bit master key for local KMS
export AEGIS_MASTER_KEY=$(openssl rand -hex 32)
export AEGIS_JWT_KEY=$(openssl rand -hex 64)

# Build, initialize durable revocation state, import one provider key from
# bounded non-terminal stdin, and issue a virtual key into a new 0600 file.
GOTOOLCHAIN=go1.26.5 make build
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
| OpenAI-compatible `POST /v1/chat/completions` path | Baseline framework implemented; other data-plane paths and methods do not enter the policy pipeline |
| Virtual key auth | Offline HS256 issuance and runtime validation implemented; RS256 is planned |
| Provider support | `openai` and OpenAI-compatible `deepseek` enabled; Anthropic/Gemini fail closed until adapters are implemented |
| KMS | Local AES-GCM v2 envelope binds ciphertext to key ID as AAD; explicit compatibility migration ends in a strict-v2 format floor; Vault is planned |
| Revocation | Versioned local snapshot, serialized atomic CLI writes, 500 ms polling, and in-memory request checks implemented for single-host deployments; shared backend is planned |
| Operator CLI | Offline revocation initialization, provider-key import, virtual-key issue/revoke, and KMS migration implemented; no network Admin API is mounted |
| Rate limiting | In-memory RPM and default/per-key concurrency baseline implemented; non-zero `default_max_concurrency` is a deployment ceiling; non-zero TPM, Redis backend, and `redis_url` fail fast until implemented |
| PII protection | Regex-based request redaction baseline implemented |
| Request memory | One bounded request-scoped body buffer is shared across policy/adapter stages and zeroed after use; provider responses are streamed |
| Cost management | Pricing/quota modules scaffolded; `quota.enabled=true` and reserved quota backend/DSN/default-budget fields are rejected until runtime enforcement exists |
| Admin API / BYOK | Handler scaffold exists but is not mounted by the main gateway; mutating/query endpoints fail closed with `501`, and `key_source="byok"` virtual keys are rejected until owner/provider binding exists |
| Streaming proxy | SSE forwarding baseline implemented; token counting is heuristic |
| mTLS | Server TLS implemented; mTLS requires `ca_file`; `min_version` is currently fixed to TLS 1.3 |

## Deployment Modes

| Mode | Dependencies | Use Case |
| :--- | :--- | :--- |
| **Framework Smoke** | Local env vars + in-memory KMS | Development validation |
| **Standalone** | Local env vars + encrypted file KMS store | Development and small-team validation |
| **Cluster** | Redis + Vault + durable quota store | Planned |

## Docker Runtime Contract

The image includes `/etc/aegis/aegis.json` derived from `aegis.example.json`, with KMS and revocation state under `/var/lib/aegis`. Initialize the volume once with the same release binary before starting the gateway:

```bash
make docker VERSION=v0.2.1-rc-local

docker volume create aegis-data
docker run --rm \
  -v aegis-data:/var/lib/aegis \
  aegis:v0.2.1-rc-local \
  operator revocation init --config /etc/aegis/aegis.json

docker run --rm \
  --read-only \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  -e AEGIS_JWT_KEY="$(openssl rand -hex 64)" \
  -v aegis-data:/var/lib/aegis \
  -p 8080:8080 \
  aegis:v0.2.1-rc-local
```

The bundled example config is non-secret and suitable only for smoke validation. If you mount a custom config, put both `kms.local.key_store_path` and `auth.revocation.file_path` on durable local storage. Import provider keys with `operator provider-key import` before real `/v1` traffic. Local revocation files are not a multi-host store and cannot detect restoration of an older valid snapshot before restart; recovery must preserve the union of unexpired tombstones.

The default Docker target tags only the explicit `VERSION`. Set `DOCKER_TAG_LATEST=true` only for a supported release.

## Security

Security is Aegis's highest priority. See [SECURITY.md](SECURITY.md) for:
- Vulnerability reporting process
- Security design principles
- Secure development guidelines

**Key security properties:**
- API keys never exist in plaintext at rest
- Memory is zeroed after credential use
- Egress filtering constrains configured provider requests to allowlisted hosts; plain entries are exact hosts and `*.example.com` is required for subdomains
- Unknown JSON configuration fields, an empty auth issuer, and a missing JWT `key_source` fail closed
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
