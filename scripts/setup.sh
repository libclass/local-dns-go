#!/bin/bash

set -e

echo "Setting up Local-DNS-Go..."

# Initialize Go module if not already done
if [ ! -f go.mod ]; then
    echo "Initializing Go module..."
    go mod init github.com/libclass/local-dns-go
fi

# Download dependencies
echo "Downloading dependencies..."
go mod tidy
go mod download

# Verify dependencies
echo "Verifying dependencies..."
go mod verify

# Build the project
echo "Building project..."
go build -o local-dns-go .

echo "Setup complete! You can now run: ./local-dns-go"


