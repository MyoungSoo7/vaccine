BINARY := vaccine
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build build-linux build-mac test fmt vet tidy clean install help

all: build

build: ## Build for current OS/arch
	go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/vaccine

build-mac: ## Cross-build macOS arm64 + amd64
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/vaccine
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 ./cmd/vaccine

build-linux: ## Cross-build Linux arm64 + amd64
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/vaccine
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/vaccine

test: ## Run tests
	go test ./...

fmt: ## gofmt
	gofmt -s -w .

vet: ## go vet
	go vet ./...

tidy: ## go mod tidy
	go mod tidy

install: build ## Install to /usr/local/bin
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)

clean: ## Remove build artifacts
	rm -f $(BINARY)
	rm -rf dist/

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
