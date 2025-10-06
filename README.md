# Local-DNS-Go

A high-performance DNS cache server with web management GUI, written in Go. Supports DNS over HTTPS (DoH), DNS over TLS (DoT), IPv6, and custom host routing.

![GitHub](https://img.shields.io/github/license/libclass/local-dns-go)
![Go Version](https://img.shields.io/golang/v/go.mod)
![Build Status](https://img.shields.io/github/actions/workflow/status/libclass/local-dns-go/go.yml)
![Docker Pulls](https://img.shields.io/docker/pulls/libclass/local-dns-go)

## Features

- 🚀 **High Performance**: In-memory caching with SQLite persistence
- 🌐 **Modern Protocols**: Full support for DoH, DoT, and IPv6
- 🎯 **Custom Routing**: Custom host-to-IP mapping rules
- 📊 **Web Management**: Beautiful web GUI for monitoring and management
- 🔒 **Security**: TLS support, input validation, and secure defaults
- 📈 **Statistics**: Real-time metrics and query analytics
- 🔧 **REST API**: Comprehensive API for integration and automation
- 🐳 **Docker Ready**: Containerized deployment support
- 🔄 **Dynamic Configuration**: Hot-reload configuration without downtime

## Quick Start

### Prerequisites

- Go 1.21 or later
- SQLite3

### Installation

```bash
# Clone the repository
git clone https://github.com/libclass/local-dns-go.git
cd local-dns-go

# Install dependencies
go mod download

# Build the server
go build -o local-dns-go .

# Run the server
./local-dns-go
```

### Using Docker

```bash
# Using Docker Compose (recommended)
docker-compose up -d

# Or using Docker directly
docker run -d \
  --name local-dns-go \
  -p 53:53/udp \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.json:/app/config.json \
  libclass/local-dns-go:latest
```

### Configuration

Create a `config.json` file:

```json
{
  "server": {
    "listen_addr": ":53",
    "http_addr": ":8080"
  },
  "dns": {
    "upstream_servers": ["8.8.8.8:53", "1.1.1.1:53"],
    "doh_endpoints": [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query"
    ],
    "cache_ttl": 300,
    "enable_ipv6": true
  },
  "database": {
    "path": "./data/dns_cache.db"
  }
}
```

See [Configuration Guide](docs/CONFIGURATION.md) for all available options.

## Usage

### Start the Server

```bash
./local-dns-go -config config.json
```

### Access Web Interface

Open your browser to `http://localhost:8080`

### Configure DNS

Set your DNS server to `127.0.0.1` or your server's IP address.

#### Linux
```bash
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

#### macOS
```bash
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1
```

#### Windows
- Network Settings → Change adapter options
- Right-click your connection → Properties
- Select "Internet Protocol Version 4 (TCP/IPv4)" → Properties
- Use the following DNS server addresses: `127.0.0.1`

## Web Management Interface

Local-DNS-Go provides a comprehensive web interface for:

- 📊 **Real-time Statistics**: Query counts, cache hits, response times
- 🔍 **Cache Management**: View, search, and clear cached DNS records
- 🛣️ **Custom Routes**: Add, edit, and delete custom host routing rules
- ⚙️ **Configuration**: Dynamic configuration updates
- 📈 **Monitoring**: Performance metrics and health status

![Web Interface](docs/images/web-interface.png)

## API Documentation

The server provides a REST API for management and integration:

### Core Endpoints

- `GET /api/stats` - Get server statistics
- `GET /api/cache` - Get cached DNS entries
- `DELETE /api/cache` - Clear DNS cache
- `GET /api/routes` - Get custom routing rules
- `POST /api/routes` - Add custom route
- `DELETE /api/routes` - Delete custom route
- `GET /api/config` - Get server configuration
- `POST /api/config` - Update server configuration
- `GET /health` - Health check endpoint

### Example Usage

```bash
# Get server statistics
curl http://localhost:8080/api/stats

# Add custom route
curl -X POST http://localhost:8080/api/routes \
  -H "Content-Type: application/json" \
  -d '{"domain":"local.dev","type":"A","target":"127.0.0.1"}'

# Clear cache
curl -X DELETE http://localhost:8080/api/cache
```

See [API Documentation](docs/API.md) for detailed information.

## Configuration Options

### Key Configuration Sections

| Section | Description |
|---------|-------------|
| `server` | Server bind addresses and timeouts |
| `dns` | DNS resolution and caching settings |
| `database` | SQLite database configuration |
| `logging` | Logging levels and output |
| `security` | Rate limiting and access controls |
| `monitoring` | Metrics and health checks |

### Example Production Configuration

```json
{
  "server": {
    "listen_addr": "0.0.0.0:53",
    "http_addr": "127.0.0.1:8080",
    "enable_https": true,
    "ssl_cert_path": "/etc/ssl/certs/local-dns-go.crt",
    "ssl_key_path": "/etc/ssl/private/local-dns-go.key"
  },
  "dns": {
    "upstream_servers": ["8.8.8.8:53", "1.1.1.1:53"],
    "doh_endpoints": ["https://cloudflare-dns.com/dns-query"],
    "dot_servers": ["1.1.1.1:853"],
    "cache_ttl": 600,
    "enable_dnssec": true,
    "prefer_secure_transport": true
  },
  "security": {
    "enable_authentication": true,
    "api_keys": ["your-secure-api-key"],
    "allowed_networks": ["192.168.1.0/24"]
  }
}
```

See [Configuration Guide](docs/CONFIGURATION.md) for complete documentation.

## Development

### Building from Source

```bash
git clone https://github.com/libclass/local-dns-go.git
cd local-dns-go
go build -o local-dns-go .
```

### Running Tests

```bash
go test ./test/...
```

### Development with Docker

```bash
# Build development image
docker build -t local-dns-go:dev .

# Run with hot-reload for development
docker run -it --rm \
  -p 53:53/udp \
  -p 8080:8080 \
  -v $(pwd):/app \
  -w /app \
  local-dns-go:dev
```

## Deployment

### Systemd Service (Linux)

1. Copy the service file:
```bash
sudo cp examples/systemd/local-dns-go.service /etc/systemd/system/
```

2. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable local-dns-go
sudo systemctl start local-dns-go
```

### Docker Compose

```bash
# Production deployment
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: local-dns-go
spec:
  replicas: 2
  selector:
    matchLabels:
      app: local-dns-go
  template:
    metadata:
      labels:
        app: local-dns-go
    spec:
      containers:
      - name: local-dns-go
        image: libclass/local-dns-go:latest
        ports:
        - containerPort: 53
          protocol: UDP
        - containerPort: 8080
          protocol: TCP
```

## Security

Local-DNS-Go includes several security features:

- 🔐 **API Authentication** (optional)
- 🚫 **Rate Limiting** to prevent abuse
- 🌐 **CORS Controls** for web interface
- 🔒 **Secure Transports** (DoH/DoT)
- 🛡️ **Domain Filtering** and access controls

See [Security Guide](docs/SECURITY.md) for security best practices.

## Monitoring

### Built-in Metrics

- Query rates and cache hit ratios
- Response time percentiles
- Memory and connection usage
- Custom route usage statistics

### Integration with Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'local-dns-go'
    static_configs:
      - targets: ['localhost:9090']
```

### Health Checks

```bash
curl http://localhost:8080/health
```

## Troubleshooting

### Common Issues

1. **Port 53 already in use**
   ```bash
   sudo systemctl stop systemd-resolved  # On Ubuntu/Debian
   ```

2. **Permission denied on port 53**
   ```bash
   sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/local-dns-go
   ```

3. **Database errors**
   ```bash
   chmod 755 ./data
   ```

### Logs

Check logs for troubleshooting:
```bash
journalctl -u local-dns-go -f  # systemd
tail -f logs/dns-server.log    # file logs
docker logs local-dns-go       # docker
```

## Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Ensure all tests pass: `go test ./...`
5. Submit a pull request

### Development Setup

```bash
# Fork and clone
git clone https://github.com/libclass/local-dns-go.git
cd local-dns-go

# Install development tools
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linters
golangci-lint run

# Run tests with coverage
go test -cover ./...
```

## Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/libclass/local-dns-go/issues)
- 💬 [Discussions](https://github.com/libclass/local-dns-go/discussions)
- 📚 [Examples](examples/)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [miekg/dns](https://github.com/miekg/dns) - DNS library for Go
- [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3) - SQLite3 driver for Go
- All contributors and users of Local-DNS-Go

<!--## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=libclass/local-dns-go&type=Date)](https://star-history.com/#libclass/local-dns-go&Date)-->

