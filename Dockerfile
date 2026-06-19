# Aegis LLM Gateway - Multi-stage Dockerfile
#
# SECURITY DESIGN:
#   - Multi-stage build: only the compiled binary enters the final image
#   - Final image: Google Distroless (no shell, no package manager, no attack surface)
#   - Runs as non-root user (nonroot:nonroot)
#   - Read-only filesystem recommended at runtime
#   - No secrets baked into the image (all via env vars at runtime)

# ============================================================
# Stage 1: Build
# ============================================================
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS builder

# Security: Base image digest is pinned; Alpine packages track repository
# security patch levels at build time.
RUN apk add --no-cache ca-certificates git

WORKDIR /build

# Cache dependencies. This project currently has no external dependencies, so
# go.sum may not exist until one is introduced.
COPY go.mod ./
RUN go mod download && go mod verify

# Copy source and build
COPY . .

# Provide a non-secret default config and writable state directory for smoke
# runs. Production deployments should mount their own config and data volume.
RUN mkdir -p /build/etc/aegis /build/var/lib/aegis \
    && cp aegis.example.json /build/etc/aegis/aegis.json \
    && sed -i 's#"key_store_path": "aegis.keys"#"key_store_path": "/var/lib/aegis/keys"#' /build/etc/aegis/aegis.json

# Build with security hardening flags:
#   -trimpath: Remove file system paths from binary
#   -ldflags: Strip debug info, set version
#   CGO_ENABLED=0: Static binary, no libc dependency
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /build/aegis \
    ./cmd/aegis

# ============================================================
# Stage 2: Runtime (Distroless)
# ============================================================
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

# Copy only the binary and CA certificates
COPY --from=builder /build/aegis /aegis
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=nonroot:nonroot /build/etc/aegis /etc/aegis
COPY --from=builder --chown=nonroot:nonroot /build/var/lib/aegis /var/lib/aegis

# Run as non-root user (UID 65534)
USER nonroot:nonroot

# Expose default port
EXPOSE 8080

# Health check endpoint
# Note: Distroless has no curl/wget, health checks should be done
# via orchestrator (K8s liveness probe) hitting /health

ENTRYPOINT ["/aegis"]
CMD ["--config", "/etc/aegis/aegis.json"]
