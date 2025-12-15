# ABOUTME: Makefile for suite-sync project
# ABOUTME: Provides build, test, and deploy targets for syncvaultd and sweet CLI

.PHONY: all build build-server build-cli test test-verbose clean run deploy logs status help

# Default target
all: build

# Build both binaries
build: build-server build-cli

# Build the sync server
build-server:
	go build -o bin/syncvaultd ./cmd/syncvaultd

# Build the CLI
build-cli:
	go build -o bin/sweet ./cmd/sweet

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with race detector
test-race:
	go test -race ./...

# Run tests with coverage
test-coverage:
	go test -coverprofile=coverage.out ./...

# Run server locally
run: build-server
	./bin/syncvaultd serve --http=0.0.0.0:8090 --dir=./pb_data

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf pb_data/

# Deploy to Fly.io
deploy:
	fly deploy

# View Fly.io logs
logs:
	fly logs

# Check Fly.io status
status:
	fly status

# Show available targets
help:
	@echo "suite-sync Makefile targets:"
	@echo ""
	@echo "  make build        - Build both syncvaultd and sweet"
	@echo "  make build-server - Build syncvaultd server"
	@echo "  make build-cli    - Build sweet CLI"
	@echo "  make test         - Run all tests"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make run          - Run server locally on :8090"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make deploy       - Deploy to Fly.io"
	@echo "  make logs         - View Fly.io logs"
	@echo "  make status       - Check Fly.io app status"
