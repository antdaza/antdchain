.PHONY: all build build-wallet build-daemon clean cross-compile install test fmt vet lint help

# Binary names
DAEMON_BINARY=antdchain
WALLET_BINARY=antdchain-wallet
VERSION?=2.0.0
BUILD_DIR=build
GO_BUILD_FLAGS=-ldflags="-s -w"
GO_TEST_FLAGS=-v
GO_RACE_FLAGS=-race

# Default target
all: build

# Build both daemon and wallet
build: build-daemon build-wallet

# Build daemon (like monerod)
build-daemon:
	@echo "🔨 Building ANTDChain daemon..."
	go build $(GO_BUILD_FLAGS) -o $(DAEMON_BINARY) ./cmd/antdchain
	@echo "✅ Daemon built: $(DAEMON_BINARY)"

# Build wallet CLI (like monero-wallet-cli)
build-wallet:
	@echo "👛 Building ANTDChain wallet CLI..."
	go build $(GO_BUILD_FLAGS) -o $(WALLET_BINARY) ./cmd/wallet-console
	@echo "✅ Wallet CLI built: $(WALLET_BINARY)"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(DAEMON_BINARY) $(WALLET_BINARY)
	rm -f $(DAEMON_BINARY)-* $(WALLET_BINARY)-*
	@echo "✅ Clean complete"

# Cross-compile for all platforms
cross-compile: clean
	@echo "🌍 Cross-compiling for all platforms..."
	mkdir -p $(BUILD_DIR)

	# Linux (64-bit, 32-bit, ARM)
	@echo "🐧 Linux..."
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-linux-amd64 ./cmd/antdchain
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-linux-amd64 ./cmd/wallet-console
	
	GOOS=linux GOARCH=386 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-linux-386 ./cmd/antdchain
	GOOS=linux GOARCH=386 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-linux-386 ./cmd/wallet-console
	
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-linux-arm64 ./cmd/antdchain
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-linux-arm64 ./cmd/wallet-console
	
	GOOS=linux GOARCH=arm go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-linux-arm ./cmd/antdchain
	GOOS=linux GOARCH=arm go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-linux-arm ./cmd/wallet-console

	# Windows
	@echo "🪟 Windows..."
	GOOS=windows GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-windows-amd64.exe ./cmd/antdchain
	GOOS=windows GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-windows-amd64.exe ./cmd/wallet-console
	
	GOOS=windows GOARCH=386 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-windows-386.exe ./cmd/antdchain
	GOOS=windows GOARCH=386 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-windows-386.exe ./cmd/wallet-console

	# macOS
	@echo "🍎 macOS..."
	GOOS=darwin GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-darwin-amd64 ./cmd/antdchain
	GOOS=darwin GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-darwin-amd64 ./cmd/wallet-console
	
	GOOS=darwin GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(DAEMON_BINARY)-darwin-arm64 ./cmd/antdchain
	GOOS=darwin GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(WALLET_BINARY)-darwin-arm64 ./cmd/wallet-console

	@echo "✅ Cross-compilation complete!"
	@echo "📁 Binaries are in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

# Install to GOPATH/bin
install:
	@echo "📦 Installing to GOPATH/bin..."
	go install ./cmd/antdchain
	go install ./cmd/wallet-console
	@echo "✅ Installed: $(DAEMON_BINARY) and $(WALLET_BINARY)"

# Quick development build
dev: clean build
	@echo "🚀 Development build complete"

# Test
test:
	@echo "🧪 Running tests..."
	go test $(GO_TEST_FLAGS) ./...

# Test with race detection
test-race:
	@echo "🏁 Running tests with race detection..."
	go test $(GO_RACE_FLAGS) $(GO_TEST_FLAGS) ./...

# Run daemon
run:
	@echo "🚀 Starting ANTDChain daemon..."
	go run ./cmd/antdchain/main.go --console

# Run daemon with mining
run-mining:
	@echo "⛏️ Starting ANTDChain daemon with mining..."
	go run ./cmd/antdchain/main.go --console --startmining

# Run wallet CLI
wallet:
	@echo "👛 Starting ANTDChain wallet CLI..."
	go run ./cmd/wallet-console/main.go

# Run wallet with custom daemon
wallet-remote:
	@echo "🌐 Starting wallet CLI with remote daemon..."
	go run ./cmd/wallet-console/main.go --daemon-url $(or $(DAEMON_URL),http://localhost:8089)

# Format code
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...

# Vet code
vet:
	@echo "🔍 Vetting code..."
	go vet ./...

# Lint code
lint:
	@echo "✨ Linting code..."
	@if command -v golangci-lint >/dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint not installed. Run: brew install golangci-lint"; \
	fi

# Generate release packages
release: cross-compile
	@echo "📦 Creating release packages..."
	
	# Linux packages
	cd $(BUILD_DIR) && tar -czf $(DAEMON_BINARY)-linux-amd64-$(VERSION).tar.gz $(DAEMON_BINARY)-linux-amd64 $(WALLET_BINARY)-linux-amd64
	cd $(BUILD_DIR) && tar -czf $(DAEMON_BINARY)-linux-arm64-$(VERSION).tar.gz $(DAEMON_BINARY)-linux-arm64 $(WALLET_BINARY)-linux-arm64
	
	# Windows packages
	cd $(BUILD_DIR) && zip $(DAEMON_BINARY)-windows-amd64-$(VERSION).zip $(DAEMON_BINARY)-windows-amd64.exe $(WALLET_BINARY)-windows-amd64.exe
	
	# macOS packages
	cd $(BUILD_DIR) && tar -czf $(DAEMON_BINARY)-darwin-amd64-$(VERSION).tar.gz $(DAEMON_BINARY)-darwin-amd64 $(WALLET_BINARY)-darwin-amd64
	cd $(BUILD_DIR) && tar -czf $(DAEMON_BINARY)-darwin-arm64-$(VERSION).tar.gz $(DAEMON_BINARY)-darwin-arm64 $(WALLET_BINARY)-darwin-arm64
	
	@echo "✅ Release packages created in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/*.tar.gz $(BUILD_DIR)/*.zip

# Build for Ubuntu/Debian
deb-build:
	@echo "🐧 Building for Ubuntu/Debian..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-linux-gnu-gcc go build -o $(BUILD_DIR)/$(DAEMON_BINARY)-ubuntu-amd64 ./cmd/antdchain
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-linux-gnu-gcc go build -o $(BUILD_DIR)/$(WALLET_BINARY)-ubuntu-amd64 ./cmd/wallet-console

# Static build (no dependencies)
static-build:
	@echo "🔒 Building static binaries..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -o $(BUILD_DIR)/$(DAEMON_BINARY)-static-linux-amd64 ./cmd/antdchain
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -o $(BUILD_DIR)/$(WALLET_BINARY)-static-linux-amd64 ./cmd/wallet-console

# Docker build
docker-build:
	@echo "🐳 Building using Docker..."
	mkdir -p $(BUILD_DIR)
	docker run --rm -v $(PWD):/app -w /app golang:1.21-alpine go build -o $(BUILD_DIR)/$(DAEMON_BINARY)-docker ./cmd/antdchain
	docker run --rm -v $(PWD):/app -w /app golang:1.21-alpine go build -o $(BUILD_DIR)/$(WALLET_BINARY)-docker ./cmd/wallet-console

# Check dependencies
deps:
	@echo "📦 Checking dependencies..."
	go mod tidy
	go mod download
	@echo "✅ Dependencies up to date"

# Show help
help:
	@echo "ANTDChain Build System"
	@echo "======================"
	@echo ""
	@echo "📦 Build Commands:"
	@echo "  make                   - Build both daemon and wallet (default)"
	@echo "  make build-daemon      - Build daemon only"
	@echo "  make build-wallet      - Build wallet CLI only"
	@echo "  make clean             - Clean build artifacts"
	@echo "  make cross-compile     - Cross-compile for all platforms"
	@echo "  make release           - Create release packages"
	@echo "  make install           - Install to GOPATH/bin"
	@echo ""
	@echo "🏃‍♂️ Run Commands:"
	@echo "  make run               - Run daemon"
	@echo "  make run-mining        - Run daemon with mining"
	@echo "  make wallet            - Run wallet CLI"
	@echo "  make wallet-remote     - Run wallet with custom daemon (set DAEMON_URL)"
	@echo ""
	@echo "🧪 Test Commands:"
	@echo "  make test              - Run tests"
	@echo "  make test-race         - Run tests with race detection"
	@echo "  make fmt               - Format code"
	@echo "  make vet               - Vet code"
	@echo "  make lint              - Lint code"
	@echo ""
	@echo "🔧 Special Builds:"
	@echo "  make deb-build         - Build for Ubuntu/Debian"
	@echo "  make static-build      - Build static binaries"
	@echo "  make docker-build      - Build using Docker"
	@echo ""
	@echo "📚 Other:"
	@echo "  make deps              - Check and update dependencies"
	@echo "  make help              - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make clean build                      # Clean rebuild"
	@echo "  DAEMON_URL=http://node:8089 make wallet-remote  # Connect to remote"
	@echo "  make cross-compile release            # Create release packages"

# Alias for backward compatibility
build-all: build
wallet-cli: build-wallet
daemon: build-daemon
