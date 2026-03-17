.PHONY: all local clean test tidy docker-build docker-build-release

all: local

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS = -X github.com/fosrl/newt/pkg/version.Version=$(VERSION) \
          -X github.com/fosrl/newt/pkg/version.Commit=$(COMMIT) \
          -X github.com/fosrl/newt/pkg/version.BuildDate=$(BUILD_DATE)

local:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o ./bin/newt ./cmd/newt

clean:
	rm -rf ./bin

test:
	go test ./...

tidy:
	go mod tidy

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
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/newt_linux_arm64 ./cmd/newt

go-build-release-linux-arm32-v7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "$(LDFLAGS)" -o bin/newt_linux_arm32 ./cmd/newt

go-build-release-linux-arm32-v6:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags "$(LDFLAGS)" -o bin/newt_linux_arm32v6 ./cmd/newt

go-build-release-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/newt_linux_amd64 ./cmd/newt

go-build-release-linux-riscv64:
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build -ldflags "$(LDFLAGS)" -o bin/newt_linux_riscv64 ./cmd/newt

go-build-release-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/newt_darwin_arm64 ./cmd/newt

go-build-release-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/newt_darwin_amd64 ./cmd/newt

go-build-release-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/newt_windows_amd64.exe ./cmd/newt

go-build-release-freebsd-amd64:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/newt_freebsd_amd64 ./cmd/newt

go-build-release-freebsd-arm64:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/newt_freebsd_arm64 ./cmd/newt
