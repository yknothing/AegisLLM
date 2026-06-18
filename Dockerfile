# Aegis LLM Gateway - Multi-stage Dockerfile
#
# SECURITY DESIGN:
#   - Multi-stage build: only the compiled binary enters the final image
#   - Final image: Google Distroless (no shell, no package manager, no attack surface)
#   - Runs as non-root user (nobody:nobody)
#   - Read-only filesystem recommended at runtime
#   - No secrets baked into the image (all via env vars at runtime)

# ============================================================
# Stage 1: Build
# ============================================================
FROM golang:1.22-alpine AS builder

# Security: Pin dependencies and verify checksums
RUN apk add --no-cache ca-certificates git

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source and build
COPY . .

# Build with security hardening flags:
#   -trimpath: Remove file system paths from binary
#   -ldflags: Strip debug info, set version
#   CGO_ENABLED=0: Static binary, no libc dependency
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /build/aegis \
    ./cmd/aegis

# ============================================================
# Stage 2: Runtime (Distroless)
# ============================================================
FROM gcr.io/distroless/static-debian12:nonroot

# Copy only the binary and CA certificates
COPY --from=builder /build/aegis /aegis
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Run as non-root user (UID 65534)
USER nonroot:nonroot

# Expose default port
EXPOSE 8080

# Health check endpoint
# Note: Distroless has no curl/wget, health checks should be done
# via orchestrator (K8s liveness probe) hitting /health

ENTRYPOINT ["/aegis"]
CMD ["--config", "/etc/aegis/aegis.json"]
