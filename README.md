# Aegis

**Security-first LLM API Gateway**

Aegis is a lightweight, secure gateway for managing access to multiple LLM providers. It provides unified API access, encrypted key management, intelligent routing, rate limiting, and cost control — all through a single binary.

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

This repository currently provides the runtime framework and a minimal OpenAI-compatible gateway path:

- Implemented baseline: safe logger, config loading, middleware composition, HS256 virtual-key validation, in-memory rate limiting, PII redaction, provider routing, local in-memory KMS backend, egress allowlist validation, and streaming proxy scaffolding.
- Explicitly not production-ready yet: persistent key store, Admin API key issuance, Vault KMS, Redis rate limiter, quota enforcement, and non-OpenAI protocol transformations.
- Fail-fast behavior: unsupported Vault KMS and Redis limiter modes are rejected instead of silently running without controls.

## Development Smoke

```bash
# Generate a 256-bit master key for local KMS
export AEGIS_MASTER_KEY=$(openssl rand -hex 32)
export AEGIS_JWT_KEY=$(openssl rand -hex 64)

# Run Aegis
./aegis --config aegis.example.json

# Verify the process is alive
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
| KMS | Local AES-GCM interface and in-memory backend implemented; persistent local store and Vault are planned |
| Rate limiting | In-memory RPM and concurrency baseline implemented; TPM and Redis are planned |
| PII protection | Regex-based request redaction baseline implemented |
| Cost management | Pricing/quota modules scaffolded; runtime enforcement is planned |
| Admin API / BYOK | Routes are scaffolded and fail closed with `501` until issuance, revocation, and storage flows are implemented |
| Streaming proxy | SSE forwarding baseline implemented; token counting is heuristic |
| mTLS | Server TLS/mTLS configuration path implemented |

## Deployment Modes

| Mode | Dependencies | Use Case |
| :--- | :--- | :--- |
| **Framework Smoke** | Local env vars + in-memory KMS | Development validation |
| **Standalone** | Persistent local KMS store | Planned |
| **Cluster** | Redis + Vault + durable quota store | Planned |

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
  kms/              → Key management (local AES + Vault)
  proxy/            → Streaming proxy engine
  quota/            → Budget and cost management
  model/            → OpenAI-compatible API types
  utils/            → Memory zeroing, safe logging
```

## Contributing

Contributions are welcome. Please read [SECURITY.md](SECURITY.md) for security guidelines before submitting code.

## License

MIT License. See [LICENSE](LICENSE).
