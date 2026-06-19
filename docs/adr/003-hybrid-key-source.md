# ADR-003: Hybrid Key Source Resolution

## Status
Accepted

## Implementation Status
Current runtime can resolve `key_source: "pool"` and `key_source: "byok"` claims once the referenced KMS key already exists. The Admin API issuance, BYOK registration, deletion, and revocation workflows are scaffolded only and are not mounted by the main gateway.

## Context
Consumer apps face a dilemma: server-hosted keys provide a great UX but expose developers to high costs and quota exhaustion risks, while Bring Your Own Key (BYOK) transfers costs to users but creates friction. We need an architecture that supports both models seamlessly without forcing the client app to implement complex logic for different tiers.

## Decision
We will use **Hybrid Key Source Resolution** based on Virtual Keys (JWT).

1. The client app will **always** authenticate using a Virtual Key (`Authorization: Bearer vk_...`).
2. The Virtual Key (a signed JWT) will contain a `key_source` claim (`"pool"` or `"byok"`).
3. If `key_source` is `"pool"`, Aegis will inject a developer-provided API key from the KMS pool.
4. If `key_source` is `"byok"`, the JWT will contain a `byok_key_id` claim. Aegis will fetch this specific user's encrypted API key from KMS if that key has already been provisioned.
5. In both cases, the real API key is fetched dynamically just before the proxy request and zeroed immediately after. Key issuance and BYOK provisioning remain future admin-control work.

## Consequences

### Positive
- **Client Simplicity**: The frontend app logic is identical for free, pro, and BYOK users.
- **Security**: The user's real API key is never stored on the device.
- **Cost Isolation Target**: Once BYOK and quota enforcement are implemented, BYOK users can use their own provider quota without affecting the developer's server-hosted pool budget.
- **Flexibility**: Users can easily switch between modes by simply requesting a new Virtual Key.

### Negative
- **State Management**: Aegis must securely store and manage user-provided API keys in its KMS, increasing the security burden on the gateway deployment.
- **Complexity**: The KMS layer must handle a potentially massive number of keys (one per BYOK user) rather than just a few developer pool keys.

## Implementation Details

The JWT claims structure will be extended:

```go
type VirtualKeyClaims struct {
    // ... existing fields
    KeySource string `json:"key_source"` // "pool" or "byok"
    BYOKKeyID string `json:"byok_key_id,omitempty"` // Used if key_source == "byok"
}
```

The KMS middleware will resolve the key dynamically:

```go
if claims.KeySource == "byok" {
    keyID = claims.BYOKKeyID
} else {
    keyID = resolveFromPool(ctx.ProviderID)
}
```
