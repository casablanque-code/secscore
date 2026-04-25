BINARY    := secscore
MODULE    := github.com/casablanque-code/secscore
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-X $(MODULE)/internal/version.Version=$(VERSION)"

BUILD_DIR := dist

.PHONY: build test vet install uninstall clean release help

## build: build binary for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/secscore

## test: run all tests
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## install: install binary to /usr/local/bin
install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed to /usr/local/bin/$(BINARY)"
	@echo "Run: secscore --version"

## uninstall: remove binary from /usr/local/bin
uninstall:
	rm -f /usr/local/bin/$(BINARY)
	@echo "Removed /usr/local/bin/$(BINARY)"

## clean: remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf $(BUILD_DIR)

## release: build binaries for all platforms
release:
	mkdir -p $(BUILD_DIR)
	GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64  ./cmd/secscore
	GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64  ./cmd/secscore
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/secscore
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/secscore
	cd $(BUILD_DIR) && sha256sum $(BINARY)-* > checksums.txt
	@echo "Binaries in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

## help: show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
