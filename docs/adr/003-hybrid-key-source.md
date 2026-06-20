# ADR-003: Hybrid Key Source Resolution

## Status
Accepted

## Implementation Status
Current `v0.2.0` runtime resolves only `key_source: "pool"`. `key_source: "byok"` fails closed until Aegis has server-side owner/provider binding for user-owned keys. The Admin API issuance, BYOK registration, deletion, and revocation workflows are scaffolded only and are not mounted by the main gateway.

## Context
Consumer apps face a dilemma: server-hosted keys provide a great UX but expose developers to high costs and quota exhaustion risks, while Bring Your Own Key (BYOK) transfers costs to users but creates friction. We need an architecture that supports both models seamlessly without forcing the client app to implement complex logic for different tiers.

## Decision
We will use **Hybrid Key Source Resolution** based on Virtual Keys (JWT).

1. The client app will **always** authenticate using a Virtual Key (`Authorization: Bearer vk_...`).
2. The Virtual Key (a signed JWT) will contain a `key_source` claim. Current runtime accepts `"pool"` only.
3. If `key_source` is `"pool"`, Aegis will inject a developer-provided API key from the KMS pool.
4. If `key_source` is `"byok"`, the request fails closed until the Admin/BYOK control plane can bind the user-owned key to the token subject and provider.
5. For supported pool requests, the real API key is fetched dynamically just before the proxy request and zeroed immediately after. Key issuance and BYOK provisioning remain future admin-control work.

## Consequences

### Positive
- **Client Simplicity Target**: Once BYOK binding exists, the frontend app logic can stay identical for free, pro, and BYOK users.
- **Security**: The user's real API key is never stored on the device.
- **Cost Isolation Target**: Once BYOK and quota enforcement are implemented, BYOK users can use their own provider quota without affecting the developer's server-hosted pool budget.
- **Flexibility Target**: Users can switch between modes by requesting a new Virtual Key after the BYOK control plane exists.

### Negative
- **State Management**: Aegis must securely store and manage user-provided API keys in its KMS, increasing the security burden on the gateway deployment.
- **Complexity**: The KMS layer must handle a potentially massive number of keys (one per BYOK user) rather than just a few developer pool keys.

## Implementation Details

The JWT claims structure will be extended:

```go
type VirtualKeyClaims struct {
    // ... existing fields
    KeySource string `json:"key_source"` // Runtime: "pool"; reserved: "byok"
    BYOKKeyID string `json:"byok_key_id,omitempty"` // Reserved until BYOK binding exists
}
```

The KMS middleware will resolve the key dynamically:

```go
if claims.KeySource == "byok" {
    failClosed()
} else {
    keyID = resolveFromPool(ctx.ProviderID)
}
```
