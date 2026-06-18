# ADR-005: Go as Implementation Language

## Status
Accepted

## Context
We evaluated several languages for implementing Aegis: Go, Rust, Python, and TypeScript. The decision criteria were security (supply chain risk, memory safety), operational simplicity (deployment, dependencies), performance (streaming proxy throughput), and developer accessibility.

## Decision
We will implement Aegis in **Go (1.22+)**.

## Rationale

| Criterion | Go | Rust | Python | TypeScript |
| :--- | :--- | :--- | :--- | :--- |
| **Supply chain risk** | Low (stdlib-rich, few deps) | Low | High (PyPI attacks) | High (npm attacks) |
| **Static binary** | Yes (CGO_ENABLED=0) | Yes | No (runtime needed) | No (Node.js needed) |
| **Memory safety** | GC + no buffer overflows | Ownership model | GC | GC |
| **Streaming perf** | Excellent (goroutines) | Excellent | Adequate (asyncio) | Adequate (streams) |
| **Deployment** | Single binary, Distroless | Single binary | Container + deps | Container + deps |
| **Developer pool** | Large | Growing | Very large | Very large |
| **Compile time** | Fast | Slow | N/A | N/A |

The critical factor is **supply chain attack surface**. The 2026 LiteLLM incident demonstrated that Python's PyPI ecosystem is vulnerable to dependency poisoning. Go's rich standard library means Aegis can be built with near-zero external dependencies, and `CGO_ENABLED=0` produces a fully static binary that runs in a Distroless container with no shell or package manager.

## Consequences

### Positive
- Single binary deployment with no runtime dependencies.
- Minimal attack surface: no interpreter, no package manager in production.
- Excellent concurrency model (goroutines) for handling thousands of streaming connections.
- Fast compilation enables rapid CI/CD cycles.

### Negative
- Go lacks Rust's compile-time memory safety guarantees (use-after-free is possible with `unsafe`).
- Generic support is newer and less mature than in other languages.
- Error handling is verbose compared to exceptions-based languages.
