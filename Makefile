.PHONY: build test lint clean setup

BINARY_NAME=local-dns-go

setup:
	@echo "Setting up project..."
	go mod init github.com/libclass/local-dns-go || true
	go mod tidy
	go mod download
	go mod verify

build: setup
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

test: setup
	@echo "Running tests..."
	go test -v -race ./...

test-cover: setup
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint: setup
	@echo "Running linters..."
	go vet ./...
	golangci-lint run

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	go clean

run: build
	@echo "Starting $(BINARY_NAME)..."
	./$(BINARY_NAME)

deps-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

help:
	@echo "Available targets:"
	@echo "  setup       - Initialize and download dependencies"
	@echo "  build       - Build the application"
	@echo "  test        - Run tests"
	@echo "  test-cover  - Run tests with coverage report"
	@echo "  lint        - Run linters"
	@echo "  clean       - Clean build artifacts"
	@echo "  run         - Build and run the application"
	@echo "  deps-update - Update dependencies"
