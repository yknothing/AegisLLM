# Aegis LLM Gateway - Build Automation
#
# Usage:
#   make build       - Build the binary
#   make test        - Run tests
#   make lint        - Run linters
#   make docker      - Build Docker image
#   make security    - Run security checks
#   make clean       - Remove build artifacts

VERSION ?= dev
COMMIT  ?= unknown
BUILD_DATE ?= unknown
GO      ?= go

export GO VERSION BUILD_DATE

GOVULNCHECK_VERSION ?= v1.4.0
GOSEC_VERSION       ?= v2.27.1
GOLANGCI_VERSION    ?= v2.12.2
DOCKER_TAG_LATEST   ?= false

BINARY  := aegis
GOFLAGS := -trimpath
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)
DOCKER_TAGS := -t aegis:$(VERSION)
ifeq ($(DOCKER_TAG_LATEST),true)
DOCKER_TAGS += -t aegis:latest
endif

.PHONY: all build build-linux test test-coverage lint fmt vet security govulncheck govulncheck-binary gosec docker local-smoke release-preflight ceo-docker-smoke rollback-drill release-manifest-schema release-closure-schema generate-key clean help

all: lint test build

## Build

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/aegis

build-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 ./cmd/aegis

## Test

test:
	$(GO) test -race -cover ./...

test-coverage:
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## Quality

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run ./...

fmt:
	gofmt -s -w .

vet:
	$(GO) vet ./...

## Security

security: govulncheck govulncheck-binary gosec

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

govulncheck-binary:
	@tmp_dir=$$(mktemp -d); \
		trap 'rm -rf "$$tmp_dir"' 0 1 2 3 15; \
		CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o "$$tmp_dir/$(BINARY)" ./cmd/aegis; \
		$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) -mode=binary "$$tmp_dir/$(BINARY)"

gosec:
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...

## Docker

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		$(DOCKER_TAGS) \
		.

local-smoke:
	@source_dir="$${CANDIDATE_SOURCE_DIR:-$$(/bin/pwd -P)}"; \
		cd /; \
		/bin/sh "$${source_dir}/scripts/local_smoke.sh"

release-preflight:
	@source_dir="$${CANDIDATE_SOURCE_DIR:-$$(/bin/pwd -P)}"; \
		cd /; \
		/bin/sh "$${source_dir}/scripts/release_preflight.sh"

ceo-docker-smoke:
	@source_dir="$${CANDIDATE_SOURCE_DIR:-$$(/bin/pwd -P)}"; \
		cd /; \
		/bin/sh "$${source_dir}/scripts/ceo_docker_smoke.sh"

# Execute the Linux-only v0.2.1 -> v0.2.0 KMS migration/rollback drill with a
# caller-supplied, already-built runner and Aegis binaries plus an independently
# verified strict input lock. Add
# ROLLBACK_DRILL_FLAGS=--allow-dirty-iteration only for non-final remediation.
rollback-drill:
	@test -n "$(RUNNER_BIN)" || (echo "RUNNER_BIN is required" >&2; exit 2)
	@test -x "$(RUNNER_BIN)" || (echo "RUNNER_BIN must be a prebuilt executable" >&2; exit 2)
	@test -n "$(CANDIDATE_BIN)" || (echo "CANDIDATE_BIN is required" >&2; exit 2)
	@test -n "$(ROLLBACK_BIN)" || (echo "ROLLBACK_BIN is required" >&2; exit 2)
	@test -n "$(INPUT_LOCK)" || (echo "INPUT_LOCK is required" >&2; exit 2)
	@test -n "$(INPUT_LOCK_SHA256)" || (echo "INPUT_LOCK_SHA256 is required" >&2; exit 2)
	"$(RUNNER_BIN)" \
		--candidate-bin "$(CANDIDATE_BIN)" \
		--rollback-bin "$(ROLLBACK_BIN)" \
		--input-lock "$(INPUT_LOCK)" \
		--input-lock-sha256 "$(INPUT_LOCK_SHA256)" \
		--repo-root "$(CURDIR)" \
		$(ROLLBACK_DRILL_FLAGS)

# This repository can validate manifest structure and exact evidence bindings,
# but cannot establish independent-human trust from caller-selected keys.
release-manifest-schema:
	@test -n "$(RELEASE_MANIFEST)" || (echo "RELEASE_MANIFEST is required" >&2; exit 2)
	$(GO) run ./cmd/aegis-release-manifest --manifest "$(RELEASE_MANIFEST)" --schema-only

# Validate a detached post-publication closure record against the exact final
# manifest bytes. This checks structure and identity bindings, not authority.
release-closure-schema:
	@test -n "$(RELEASE_MANIFEST)" || (echo "RELEASE_MANIFEST is required" >&2; exit 2)
	@test -n "$(RELEASE_CLOSURE)" || (echo "RELEASE_CLOSURE is required" >&2; exit 2)
	$(GO) run ./cmd/aegis-release-manifest \
		--manifest "$(RELEASE_MANIFEST)" \
		--closure "$(RELEASE_CLOSURE)" \
		--schema-only

## Utilities

generate-key:
	@echo "Master Key: $$(openssl rand -hex 32)"
	@echo "JWT Key:    $$(openssl rand -hex 64)"

clean:
	rm -rf bin/ coverage.out coverage.html

## Help

help:
	@echo "Aegis LLM Gateway - Build Targets"
	@echo ""
	@echo "  build          Build the binary"
	@echo "  build-linux    Cross-compile for Linux"
	@echo "  test           Run tests with race detector"
	@echo "  lint           Run golangci-lint"
	@echo "  security       Run source/binary govulncheck and gosec"
	@echo "  docker         Build Docker image"
	@echo "  local-smoke    Convenience-only non-final smoke wrapper (not a trusted release launcher)"
	@echo "  release-preflight  Convenience-only non-final gate wrapper (not a trusted release launcher)"
	@echo "  ceo-docker-smoke   Convenience-only non-final Docker wrapper (not a trusted release launcher)"
	@echo "  rollback-drill     Run the prebuilt Linux v0.2.1 -> v0.2.0 rollback drill"
	@echo "  release-manifest-schema  Validate external manifest schema (not release approval)"
	@echo "  release-closure-schema  Validate post-publication closure bindings (not release approval)"
	@echo "  generate-key   Generate random encryption keys"
	@echo "  clean          Remove build artifacts"
