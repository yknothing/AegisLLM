# Aegis LLM Gateway - Build Automation
#
# Usage:
#   make build       - Build the binary
#   make test        - Run tests
#   make lint        - Run linters
#   make docker      - Build Docker image
#   make security    - Run security checks
#   make clean       - Remove build artifacts

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_DATE ?= $(DATE)
GO      ?= go

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

.PHONY: all build build-linux test test-coverage lint fmt vet security govulncheck gosec docker release-preflight ceo-docker-smoke generate-key clean help

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

security: govulncheck gosec

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

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

release-preflight:
	GO=$(GO) VERSION=$(VERSION) scripts/release_preflight.sh

ceo-docker-smoke:
	VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_DATE=$(BUILD_DATE) scripts/ceo_docker_smoke.sh

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
	@echo "  security       Run govulncheck and gosec"
	@echo "  docker         Build Docker image"
	@echo "  release-preflight  Run local release gates"
	@echo "  ceo-docker-smoke   Run Docker smoke on the ceo Mac mini"
	@echo "  generate-key   Generate random encryption keys"
	@echo "  clean          Remove build artifacts"
