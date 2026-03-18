.PHONY: all local clean test tidy lint docker-build docker-build-release

all: local

GO ?= go
GOLANGCI_LINT ?= golangci-lint
BIN_DIR ?= ./bin
MAIN_PKG := ./cmd/newt

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS = -X github.com/fosrl/newt/pkg/version.Version=$(VERSION) \
          -X github.com/fosrl/newt/pkg/version.Commit=$(COMMIT) \
          -X github.com/fosrl/newt/pkg/version.BuildDate=$(BUILD_DATE)

local:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt $(MAIN_PKG)

clean:
	rm -rf $(BIN_DIR)

test:
	$(GO) test ./...

lint:
	$(GOLANGCI_LINT) run ./...

tidy:
	$(GO) mod tidy

docker-build:
	docker build -t fosrl/newt:latest .

docker-build-release:
	@if [ -z "$(tag)" ]; then \
		echo "Error: tag is required. Usage: make docker-build-release tag=<tag>"; \
		exit 1; \
	fi
	docker buildx build . \
		--platform linux/arm/v7,linux/arm64,linux/amd64 \
		-t fosrl/newt:latest \
		-t fosrl/newt:$(tag) \
		-f Dockerfile \
		--push

.PHONY: go-build-release \
        go-build-release-linux-arm64 go-build-release-linux-arm32-v7 \
        go-build-release-linux-arm32-v6 go-build-release-linux-amd64 \
        go-build-release-linux-riscv64 go-build-release-darwin-arm64 \
        go-build-release-darwin-amd64 go-build-release-windows-amd64 \
        go-build-release-freebsd-amd64 go-build-release-freebsd-arm64

go-build-release: \
    go-build-release-linux-arm64 \
    go-build-release-linux-arm32-v7 \
    go-build-release-linux-arm32-v6 \
    go-build-release-linux-amd64 \
    go-build-release-linux-riscv64 \
    go-build-release-darwin-arm64 \
    go-build-release-darwin-amd64 \
    go-build-release-windows-amd64 \
    go-build-release-freebsd-amd64 \
    go-build-release-freebsd-arm64

go-build-release-linux-arm64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_linux_arm64 $(MAIN_PKG)

go-build-release-linux-arm32-v7:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_linux_arm32 $(MAIN_PKG)

go-build-release-linux-arm32-v6:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_linux_arm32v6 $(MAIN_PKG)

go-build-release-linux-amd64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_linux_amd64 $(MAIN_PKG)

go-build-release-linux-riscv64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_linux_riscv64 $(MAIN_PKG)

go-build-release-darwin-arm64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_darwin_arm64 $(MAIN_PKG)

go-build-release-darwin-amd64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_darwin_amd64 $(MAIN_PKG)

go-build-release-windows-amd64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_windows_amd64.exe $(MAIN_PKG)

go-build-release-freebsd-amd64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_freebsd_amd64 $(MAIN_PKG)

go-build-release-freebsd-arm64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/newt_freebsd_arm64 $(MAIN_PKG)
