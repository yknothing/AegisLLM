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

BINARY  := aegis
GOFLAGS := -trimpath
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(DATE)

.PHONY: all build test lint docker security clean

all: lint test build

## Build

build:
	mkdir -p bin
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/aegis

build-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 ./cmd/aegis

## Test

test:
	go test -race -cover ./...

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Quality

lint:
	@command -v golangci-lint >/dev/null 2>&1 || echo "Install: https://golangci-lint.run/usage/install/"
	golangci-lint run ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

## Security

security: govulncheck gosec

govulncheck:
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

gosec:
	@command -v gosec >/dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -quiet ./...

## Docker

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(DATE) \
		-t aegis:$(VERSION) \
		-t aegis:latest \
		.

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
	@echo "  generate-key   Generate random encryption keys"
	@echo "  clean          Remove build artifacts"
