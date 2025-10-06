# Security Guide

## Security Features

Local-DNS-Go includes several security features to protect your infrastructure:

### Network Security
- **Binding Controls**: Configurable listen addresses
- **Firewall Friendly**: Works with existing firewall rules
- **Proxy Support**: Trusted proxy configuration for accurate client IPs
- **Network Isolation**: Configurable allowed networks

### API Security
- **Rate Limiting**: Prevents API abuse
- **CORS Controls**: Configurable cross-origin requests
- **Authentication**: Optional API key authentication
- **Input Validation**: Comprehensive request validation

### DNS Security
- **Secure Transports**: Support for DoH and DoT
- **Query Validation**: DNS query sanitization
- **Response Verification**: Optional DNSSEC support
- **Domain Filtering**: Block malicious domains

## Security Configuration

### Recommended Production Settings

```json
{
  "server": {
    "http_addr": "127.0.0.1:8080",
    "enable_https": true,
    "ssl_cert_path": "/etc/ssl/certs/local-dns-go.crt",
    "ssl_key_path": "/etc/ssl/private/local-dns-go.key"
  },
  "security": {
    "enable_rate_limiting": true,
    "requests_per_second": 50,
    "trusted_proxies": ["127.0.0.1"],
    "cors_allowed_origins": ["https://your-domain.com"],
    "enable_authentication": true,
    "api_keys": ["your-secure-api-key"],
    "blocked_domains": ["malware.com", "phishing.org"],
    "allowed_networks": ["10.0.0.0/8", "192.168.0.0/16"]
  }
}
```

## Security Best Practices

### 1. Run with Least Privilege

```bash
# Create dedicated user
sudo useradd -r -s /bin/false localdnsuser

# Set ownership
sudo chown localdnsuser:localdnsuser /usr/local/bin/local-dns-go
sudo chown -R localdnsuser:localdnsuser /var/lib/local-dns-go

# Run as non-root with port binding capability
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/local-dns-go
```

### 2. File System Security

```bash
# Secure configuration files
chmod 600 /etc/local-dns-go/config.json
chown localdnsuser:localdnsuser /etc/local-dns-go/config.json

# Secure database and logs
chmod 755 /var/lib/local-dns-go
chown localdnsuser:localdnsuser /var/lib/local-dns-go/data
```

### 3. SSL/TLS Configuration

When using HTTPS:

```bash
# Generate SSL certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/local-dns-go.key \
  -out /etc/ssl/certs/local-dns-go.crt

# Secure private key
chmod 400 /etc/ssl/private/local-dns-go.key
chown root:root /etc/ssl/private/local-dns-go.key
```

## Reporting Security Issues

If you discover a security vulnerability in Local-DNS-Go, please report it responsibly:

1. **Do NOT create a public issue**
2. **Use GitHub security advisory feature**
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fixes

## Local-DNS-Go Specific Security Notes

### DNS Cache Security
- Cache entries are validated before use
- TTL enforcement prevents stale data
- Separate memory and database caching layers

### Web Interface Security
- CSRF protection enabled by default
- XSS prevention through template escaping
- Secure headers configuration

### Database Security
- SQLite database with proper file permissions
- Input sanitization for all database operations
- Regular backup and integrity checks
```

