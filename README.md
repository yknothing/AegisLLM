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

Architecture truth surface: `v0.2.0`, superseding the `v0.1.0` scaffold baseline that exposed planned capabilities without consistent fail-fast guards.

This repository currently provides the runtime framework and a minimal OpenAI-compatible gateway path:

- Implemented baseline: safe logger, config loading, middleware composition, HS256 virtual-key validation, in-memory rate limiting, PII redaction, provider routing, local encrypted file KMS backend, egress allowlist validation, and streaming proxy scaffolding.
- Explicitly not production-ready yet: Admin API key issuance, Vault KMS, Redis rate limiter, quota/TPM enforcement, and non-OpenAI protocol transformations.
- Fail-fast behavior: unsupported Vault KMS, Redis limiter, quota enforcement, and non-zero TPM configuration are rejected instead of silently running without controls.

## Development Smoke

```bash
# Generate a 256-bit master key for local KMS
export AEGIS_MASTER_KEY=$(openssl rand -hex 32)
export AEGIS_JWT_KEY=$(openssl rand -hex 64)

# Build and run Aegis in one terminal
make build
./bin/aegis --config aegis.example.json

# Verify the process is alive from another terminal
curl http://localhost:8080/health
```

The current baseline does not yet include a production key issuance and provider-key seeding flow. After that flow exists, OpenAI-compatible clients should point at Aegis like this:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="vk_your_virtual_key_here"
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello!"}],
    stream=True
)
```

## Capability Status

| Capability | Status |
| :--- | :--- |
| OpenAI-compatible `/v1/chat/completions` path | Baseline framework implemented |
| Virtual key auth | HS256 validation implemented; RS256 is planned |
| Provider support | `openai` and OpenAI-compatible `deepseek` enabled; Anthropic/Gemini fail closed until adapters are implemented |
| KMS | Local AES-GCM interface with in-memory and encrypted file backends implemented; Vault is planned |
| Rate limiting | In-memory RPM and concurrency baseline implemented; non-zero TPM and Redis fail fast until implemented |
| PII protection | Regex-based request redaction baseline implemented |
| Cost management | Pricing/quota modules scaffolded; `quota.enabled=true` is rejected until runtime enforcement exists |
| Admin API / BYOK | Handler scaffold exists but is not mounted by the main gateway; mutating/query endpoints fail closed with `501` |
| Streaming proxy | SSE forwarding baseline implemented; token counting is heuristic |
| mTLS | Server TLS implemented; mTLS requires `ca_file`; `min_version` is currently fixed to TLS 1.3 |

## Deployment Modes

| Mode | Dependencies | Use Case |
| :--- | :--- | :--- |
| **Framework Smoke** | Local env vars + in-memory KMS | Development validation |
| **Standalone** | Local env vars + encrypted file KMS store | Development and small-team validation |
| **Cluster** | Redis + Vault + durable quota store | Planned |

## Docker Runtime Contract

The image includes `/etc/aegis/aegis.json` derived from `aegis.example.json` with `kms.local.key_store_path` set to `/var/lib/aegis/keys`, and creates `/var/lib/aegis` for the local encrypted key store. Production deployments should mount a writable data volume and may mount their own config explicitly:

```bash
docker run --rm \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  -e AEGIS_JWT_KEY="$(openssl rand -hex 64)" \
  -v aegis-data:/var/lib/aegis \
  -p 8080:8080 \
  aegis:latest
```

The bundled example config is non-secret and suitable only for smoke validation. If you mount a custom config at `/etc/aegis/aegis.json`, set `kms.local.key_store_path` to a path backed by a writable volume. Provider API keys must still be seeded into KMS before real `/v1` provider calls can succeed.

## Security

Security is Aegis's highest priority. See [SECURITY.md](SECURITY.md) for:
- Vulnerability reporting process
- Security design principles
- Secure development guidelines

**Key security properties:**
- API keys never exist in plaintext at rest
- Memory is zeroed after credential use
- Egress filtering prevents data exfiltration
- No shell or package manager in production image

## Project Structure

```
cmd/aegis/          → Application entry point
internal/
  config/           → Configuration loading and validation
  server/           → HTTP server and middleware pipeline
  middleware/       → Auth, rate limit, PII, router, KMS, adapter
  kms/              → Key management (local AES implemented; Vault reserved)
  proxy/            → Streaming proxy engine
  quota/            → Budget and cost management
  model/            → OpenAI-compatible API types
  utils/            → Memory zeroing, safe logging
```

## Contributing

Contributions are welcome. Please read [SECURITY.md](SECURITY.md) for security guidelines before submitting code.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT License. See [LICENSE](LICENSE).
