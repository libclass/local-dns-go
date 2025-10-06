# API Documentation

## Base URL

All API endpoints are relative to the HTTP management interface address (default: `http://localhost:8080`).

## Authentication

Currently, the API does not require authentication. For production use, enable authentication in the configuration:

```json
{
  "security": {
    "enable_authentication": true,
    "api_keys": ["your-api-key-here"]
  }
}
```

When enabled, include the API key in the header:
```http
X-API-Key: your-api-key-here
```

## Endpoints

### Cache Management

#### Get Cache Entries
```http
GET /api/cache
```

**Response:**
```json
{
  "entries": [
    {
      "id": 1,
      "domain": "google.com",
      "type": "A",
      "address": "142.251.42.14",
      "ttl": 300,
      "created_at": "2024-01-01T10:00:00Z",
      "updated_at": "2024-01-01T10:05:00Z"
    }
  ],
  "total": 1
}
```

#### Clear Cache
```http
DELETE /api/cache
```

**Response:**
```json
{
  "status": "success",
  "message": "Cache cleared successfully",
  "cleared_entries": 150
}
```

### Custom Routes

#### Get Routes
```http
GET /api/routes
```

**Response:**
```json
{
  "routes": [
    {
      "id": 1,
      "domain": "internal.example.com",
      "type": "A",
      "target": "192.168.1.100",
      "enabled": true,
      "created_at": "2024-01-01T10:00:00Z"
    }
  ],
  "total": 1
}
```

#### Add Route
```http
POST /api/routes
Content-Type: application/json

{
  "domain": "test.example.com",
  "type": "A",
  "target": "192.168.1.200",
  "enabled": true
}
```

**Response:**
```json
{
  "id": 2,
  "domain": "test.example.com",
  "type": "A",
  "target": "192.168.1.200",
  "enabled": true,
  "created_at": "2024-01-01T10:10:00Z"
}
```

#### Delete Route
```http
DELETE /api/routes?id=2
```

**Response:**
```json
{
  "status": "success",
  "message": "Route deleted successfully"
}
```

### Statistics

#### Get Server Statistics
```http
GET /api/stats
```

**Response:**
```json
{
  "queries_total": 1500,
  "cache_hits": 1200,
  "cache_misses": 300,
  "custom_routes_used": 45,
  "uptime_seconds": 86400,
  "memory_usage_mb": 45.2,
  "cache_size": 500,
  "response_times": {
    "avg_ms": 12.5,
    "p95_ms": 25.1,
    "p99_ms": 50.3
  }
}
```

### Configuration

#### Get Configuration
```http
GET /api/config
```

**Response:**
```json
{
  "server": {
    "listen_addr": ":53",
    "http_addr": ":8080"
  },
  "dns": {
    "upstream_servers": ["8.8.8.8:53"],
    "cache_ttl": 300
  }
}
```

#### Update Configuration
```http
POST /api/config
Content-Type: application/json

{
  "dns": {
    "cache_ttl": 600
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration updated successfully"
}
```

### Health Check

#### Server Health
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T10:00:00Z",
  "uptime_seconds": 86400,
  "database_connected": true,
  "cache_operational": true
}
```

## Error Responses

All endpoints may return standard error responses:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid domain format",
    "details": "Domain must be a valid hostname"
  }
}
```

### Common Error Codes

- `INVALID_REQUEST` - Malformed request data
- `NOT_FOUND` - Resource not found
- `DATABASE_ERROR` - Database operation failed
- `CONFIG_ERROR` - Configuration error
- `RATE_LIMITED` - Rate limit exceeded

## Rate Limiting

When enabled, the API implements rate limiting:

- Default: 100 requests per minute per IP
- Configurable via `security.requests_per_second`

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## Examples

### Using curl

```bash
# Get cache entries
curl http://localhost:8080/api/cache

# Add custom route
curl -X POST http://localhost:8080/api/routes \
  -H "Content-Type: application/json" \
  -d '{"domain":"local.dev","type":"A","target":"127.0.0.1"}'

# Clear cache
curl -X DELETE http://localhost:8080/api/cache
```

### Using Python

```python
import requests

BASE_URL = "http://localhost:8080/api"

# Get statistics
response = requests.get(f"{BASE_URL}/stats")
print(response.json())

# Add route
route_data = {
    "domain": "test.local",
    "type": "A", 
    "target": "192.168.1.100"
}
response = requests.post(f"{BASE_URL}/routes", json=route_data)
print(response.json())
```

## Local-DNS-Go Specific Endpoints

### DNS Query Testing
```http
POST /api/query-test
Content-Type: application/json

{
  "domain": "example.com",
  "type": "A"
}
```

**Response:**
```json
{
  "domain": "example.com",
  "type": "A",
  "answers": ["93.184.216.34"],
  "response_time_ms": 45.2,
  "source": "cache"
}
```

### Cache Statistics
```http
GET /api/cache/stats
```

**Response:**
```json
{
  "total_entries": 500,
  "memory_entries": 150,
  "database_entries": 350,
  "hit_rate": 0.85,
  "evictions": 25
}
```

