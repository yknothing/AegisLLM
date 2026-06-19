# App Integration Strategy: LLM Access Patterns

This document describes how consumer-facing applications should integrate with Aegis to manage LLM access across different user tiers and key ownership models.

## Overview

Consumer apps face a fundamental three-way tension when integrating LLM capabilities: **who holds the keys**, **who bears the cost**, and **who controls access**. Aegis resolves this through a unified Virtual Key abstraction that supports multiple underlying key sources transparently.

Current runtime status: the gateway supports server-hosted pool keys when provider keys have already been seeded into KMS. BYOK registration, virtual-key issuance, revocation, usage dashboard APIs, quota enforcement, and TPM enforcement are planned control-plane work and are not current runtime capabilities.

## Access Modes

| Mode | Key Holder | Cost Bearer | Best For |
| :--- | :--- | :--- | :--- |
| **Server-Hosted (Pool)** | Developer | Developer (via subscription) | Mass-market consumer apps |
| **BYOK (Bring Your Own Key)** | User | User | Power users, developers |
| **Hybrid (Recommended)** | Both | Split by tier | Balanced growth strategy |

## Recommended Architecture: Layered Hybrid Model

The hybrid model provides zero-friction onboarding while offering flexibility for advanced users.

### User Tier Mapping

| Tier | Key Source | Quota | Model Access |
| :--- | :--- | :--- | :--- |
| Free | Server pool | Strict (e.g., 10 req/day) | Lightweight models only |
| Pro (Subscription) | Server pool | Generous (per plan) | All models |
| BYOK | User-owned | Unlimited (user's responsibility) | All models |

### Request Flow

```
App Client
    │
    │  (carries Virtual Key in Authorization header)
    ▼
┌─────────────────────────────────────────────────┐
│                  Aegis Gateway                    │
├─────────────────────────────────────────────────┤
│  1. Auth Middleware: Validate Virtual Key (JWT)  │
│  2. Resolve Key Source from JWT claims           │
│     ├── key_source = "pool" → Pool Key from KMS │
│     └── key_source = "byok" → User Key from KMS │
│  3. Rate Limit (per Virtual Key)                 │
│  4. Route to Provider                            │
│  5. Inject Real API Key                          │
│  6. Proxy Request                                │
└─────────────────────────────────────────────────┘
    │
    ▼
LLM Provider (OpenAI / Anthropic / etc.)
```

### Key Insight

The App client **never** distinguishes between pool and BYOK modes. It always sends the same Virtual Key in the `Authorization: Bearer vk_xxx` header. The mode resolution happens entirely within Aegis based on JWT claims.

## Virtual Key JWT Claims

```json
{
  "kid": "vk_abc123",
  "sub": "user_456",
  "iss": "aegis",
  "key_source": "pool",
  "pool_group": "default",
  "models": ["gpt-4o", "gpt-4o-mini", "claude-sonnet-4-20250514"],
  "rpm": 60,
  "tpm": 0,
  "budget": 0,
  "iat": 1718700000,
  "exp": 1721292000
}
```

For BYOK users, the claims differ:

```json
{
  "kid": "vk_xyz789",
  "sub": "user_456",
  "iss": "aegis",
  "key_source": "byok",
  "byok_key_id": "user-456-openai",
  "models": ["*"],
  "rpm": 0,
  "tpm": 0,
  "budget": 0,
  "iat": 1718700000,
  "exp": 1721292000
}
```

Current runtime accepts non-zero virtual-key `rpm` claims for per-key request limiting. Provider config `max_rpm` and `max_tpm` values are reserved and must be `0` until provider-level throttle and TPM enforcement are implemented. Virtual-key `tpm` and `budget` claims are also reserved and must be `0` until TPM and quota enforcement are implemented.

## BYOK Workflow

1. User navigates to App settings and enters their API key
2. App sends the key to the planned Aegis Admin API: `POST /admin/keys/byok`
3. Aegis encrypts the key via KMS and stores it with ID `user-{uid}-{provider}`
4. Aegis generates a new Virtual Key (JWT) with `key_source: "byok"`
5. App stores the Virtual Key and uses it for all subsequent requests
6. User's real API key is never stored on the client device

### Security Guarantees for BYOK

- User's real key is encrypted at rest (AES-256-GCM) in Aegis KMS
- Key is decrypted only in memory, only for the duration of a single request
- Key bytes are zeroed after the upstream transport returns response headers; Go header strings cannot be explicitly zeroed
- User can revoke their BYOK key at any time via `DELETE /admin/keys/byok/{id}`
- Aegis never logs or exposes the real key in any API response

## Implementation Phases

**Phase 1 (MVP)**: Server-hosted pool only. Runtime enforces model permission, RPM, and concurrency. Quota/TPM claims are reserved until enforcement is implemented.

**Phase 2 (Growth)**: Introduce subscription tiers. Differentiate by model access and quota.

**Phase 3 (Maturity)**: Open BYOK for power users. Add usage dashboard API.

## Related ADRs

- [ADR-001: Virtual Key as Universal Access Token](adr/001-virtual-key-design.md)
- [ADR-002: Dual-Layer KMS Architecture](adr/002-dual-layer-kms.md)
- [ADR-003: Hybrid Key Source Resolution](adr/003-hybrid-key-source.md)
- [ADR-004: Middleware Pipeline Order](adr/004-middleware-pipeline-order.md)
- [ADR-005: Go as Implementation Language](adr/005-language-choice.md)
