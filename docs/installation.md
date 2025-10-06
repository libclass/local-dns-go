# Installation Guide

## System Requirements

- **Operating System**: Linux, macOS, Windows, or any system with Go support
- **Memory**: Minimum 512MB RAM, 1GB recommended
- **Storage**: 100MB free space for database and logs
- **Network**: Outbound DNS access (port 53 UDP/TCP)

## Installation Methods

### Method 1: Binary Download

Download the latest release from the [releases page](https://github.com/libclass/local-dns-go/releases):

```bash
# Linux
wget https://github.com/libclass/local-dns-go/releases/latest/download/local-dns-go-linux-amd64
chmod +x local-dns-go-linux-amd64
sudo mv local-dns-go-linux-amd64 /usr/local/bin/local-dns-go

# macOS
wget https://github.com/libclass/local-dns-go/releases/latest/download/local-dns-go-darwin-amd64
chmod +x local-dns-go-darwin-amd64
sudo mv local-dns-go-darwin-amd64 /usr/local/bin/local-dns-go
```

### Method 2: Build from Source

```bash
git clone https://github.com/libclass/local-dns-go.git
cd local-dns-go
go build -o local-dns-go .
sudo cp local-dns-go /usr/local/bin/
```

### Method 3: Docker

```bash
docker run -d \
  --name local-dns-go \
  -p 53:53/udp \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.json:/app/config.json \
  libclass/local-dns-go:latest
```

### Method 4: Docker Compose

```bash
git clone https://github.com/libclass/local-dns-go.git
cd local-dns-go/examples
docker-compose up -d
```

## Configuration

### Basic Configuration

1. Copy the example configuration:
```bash
cp config.json.example config.json
```

2. Edit `config.json` for your environment:
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

### Advanced Configuration

See [configuration.md](configuration.md) for detailed configuration options.

## Running Local-DNS-Go

### Basic Usage

```bash
./local-dns-go -config config.json
```

### Systemd Service (Linux)

1. Create a service file:
```bash
sudo cp examples/systemd/local-dns-go.service /etc/systemd/system/
```

2. Edit the service file to match your installation path

3. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable local-dns-go
sudo systemctl start local-dns-go
```

### Verifying Installation

1. Check if the server is running:
```bash
systemctl status local-dns-go
```

2. Test DNS resolution:
```bash
dig @127.0.0.1 google.com
```

3. Access the web interface:
   Open `http://localhost:8080` in your browser

## Firewall Configuration

### Linux (iptables)
```bash
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

### Linux (ufw)
```bash
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
sudo ufw allow 8080/tcp
```

## Client Configuration

### Linux
Edit `/etc/resolv.conf`:
```bash
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

### macOS
```bash
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1
```

### Windows
- Network Settings → Change adapter options
- Right-click your connection → Properties
- Select "Internet Protocol Version 4 (TCP/IPv4)" → Properties
- Use the following DNS server addresses: 127.0.0.1

## Troubleshooting

### Common Issues

1. **Port 53 already in use**
   ```bash
   sudo netstat -tulpn | grep :53
   sudo systemctl stop systemd-resolved  # On Ubuntu/Debian
   ```

2. **Permission denied**
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
tail -f logs/local-dns-go.log  # file logs
```

### Health Check

```bash
curl http://localhost:8080/api/stats
```

