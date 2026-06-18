# AGENTS.md - AegisLLM Development Guidelines

## Project Overview

AegisLLM (Aegis) is a security-first LLM API gateway written in Go. It provides unified access, encrypted key management, intelligent routing, rate limiting, and cost control for multiple LLM providers.

## Architecture

- **Pattern**: Microkernel + Middleware Pipeline (Onion Model)
- **Language**: Go 1.22+
- **Priority**: Security > Elegance > Robustness > Usability > Lightweight

## Security Rules (MANDATORY)

1. **NEVER** log request/response bodies (prompts, completions, messages)
2. **NEVER** store API keys in plaintext — always use KMS layer
3. **ALWAYS** call `utils.MemZero()` or `SecureBytes.Close()` after using credentials
4. **ALWAYS** use `crypto/subtle.ConstantTimeCompare` for token validation
5. **ALWAYS** validate egress domains before making outbound requests
6. **NEVER** include secrets in error messages returned to clients
7. **NEVER** add dependencies without security review

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Every package must have a doc comment explaining its security properties
- Every function handling secrets must document its zeroing behavior
- Use `internal/` for all private packages (prevents external import)

## Testing

- All security-critical paths must have unit tests
- Use `go test -race` to detect data races
- Run `govulncheck` before merging

## File Structure

```
cmd/aegis/          → Entry point
internal/
  config/           → Configuration (no plaintext secrets)
  server/           → HTTP server + pipeline
  middleware/       → Auth, RateLimit, PII, Router, KMS, Adapter
  kms/              → Key management (local + vault)
  proxy/            → Streaming proxy engine
  quota/            → Budget management
  model/            → API type definitions
  utils/            → MemZero, safe logging
```
