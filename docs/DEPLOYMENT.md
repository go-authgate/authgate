# Deployment Guide

This guide covers production deployment options for AuthGate, including binary deployment, Docker, reverse proxy setup, and cloud platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Binary Deployment (Systemd)](#binary-deployment-systemd)
- [Docker Deployment](#docker-deployment)
  - [Docker Features](#docker-features)
  - [Docker Compose](#docker-compose)
- [Reverse Proxy Setup (Nginx)](#reverse-proxy-setup-nginx)
- [Cloud Platform Deployment](#cloud-platform-deployment)
  - [Fly.io](#flyio)
- [Production Checklist](#production-checklist)

---

## Prerequisites

Before deploying AuthGate to production:

- [ ] Generate strong JWT and session secrets
- [ ] Set up a PostgreSQL database (recommended for production) or SQLite
- [ ] Obtain SSL/TLS certificates (via Let's Encrypt or your certificate authority)
- [ ] Configure firewall rules
- [ ] Set up backup strategy for the database
- [ ] Review the [Security Guide](SECURITY.md)

---

## Binary Deployment (Systemd)

### Step 1: Build Static Binary

```bash
# Build static binary for Linux (CGO disabled)
make build_linux_amd64

# Output: release/linux/amd64/authgate
```

### Step 2: Deploy to Server

```bash
# Copy binary to server
scp release/linux/amd64/authgate user@server:/usr/local/bin/

# Set executable permissions
ssh user@server "chmod +x /usr/local/bin/authgate"
```

### Step 3: Create Service User

```bash
# Create dedicated user for AuthGate
sudo useradd -r -s /bin/false -d /var/lib/authgate authgate

# Create working directory
sudo mkdir -p /var/lib/authgate
sudo chown authgate:authgate /var/lib/authgate

# Create config directory
sudo mkdir -p /etc/authgate
sudo chown authgate:authgate /etc/authgate
```

### Step 4: Configure Environment

Create `/etc/authgate/.env`:

```bash
# Server Configuration
SERVER_ADDR=:8080
BASE_URL=https://auth.yourdomain.com

# Security (REQUIRED - generate with: openssl rand -hex 32)
JWT_SECRET=your-256-bit-secret-change-in-production
SESSION_SECRET=session-secret-change-in-production

# Database
DATABASE_DRIVER=sqlite
DATABASE_DSN=/var/lib/authgate/oauth.db

# Or PostgreSQL:
# DATABASE_DRIVER=postgres
# DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=require"

# Admin Password (REQUIRED)
DEFAULT_ADMIN_PASSWORD=your-secure-admin-password

# Rate Limiting
ENABLE_RATE_LIMIT=true
RATE_LIMIT_STORE=memory

# Audit Logging
ENABLE_AUDIT_LOGGING=true
AUDIT_LOG_RETENTION=2160h
```

Set proper permissions:

```bash
sudo chown authgate:authgate /etc/authgate/.env
sudo chmod 600 /etc/authgate/.env
```

### Step 5: Create Systemd Service

Create `/etc/systemd/system/authgate.service`:

```ini
[Unit]
Description=AuthGate OAuth Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=authgate
Group=authgate
WorkingDirectory=/var/lib/authgate
ExecStart=/usr/local/bin/authgate server
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/authgate

# Environment
EnvironmentFile=/etc/authgate/.env

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=authgate

[Install]
WantedBy=multi-user.target
```

### Step 6: Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable authgate

# Start service
sudo systemctl start authgate

# Check status
sudo systemctl status authgate

# View logs
sudo journalctl -u authgate -f
```

---

## Docker Deployment

### Docker Features

- Alpine-based (minimal attack surface)
- Multi-architecture support (amd64, arm64)
- Runs as non-root user (UID 1000)
- Built-in health check endpoint
- Persistent volume for SQLite database
- Embedded templates and static files (single binary)
- Version labels via `--build-arg VERSION=<version>`

### Build Docker Image

```bash
# Build for your platform with version tag
VERSION=$(git describe --tags --always --dirty)
docker build -f docker/Dockerfile \
  --build-arg VERSION=${VERSION} \
  -t authgate:${VERSION} \
  -t authgate:latest \
  .

# Or build without version (defaults to "dev")
docker build -f docker/Dockerfile -t authgate .

# Verify version
docker inspect authgate:latest --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
```

### Run with Docker

```bash
# Generate secrets
JWT_SECRET=$(openssl rand -hex 32)
SESSION_SECRET=$(openssl rand -hex 32)

# Run container
docker run -d \
  --name authgate \
  --restart unless-stopped \
  -p 8080:8080 \
  -v authgate-data:/app/data \
  -e JWT_SECRET=${JWT_SECRET} \
  -e SESSION_SECRET=${SESSION_SECRET} \
  -e BASE_URL=https://auth.yourdomain.com \
  -e DATABASE_PATH=/app/data/oauth.db \
  -e DEFAULT_ADMIN_PASSWORD=your-secure-password \
  authgate:latest

# Check health
curl http://localhost:8080/health

# View logs
docker logs -f authgate
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: "3.8"

services:
  authgate:
    image: authgate:latest
    container_name: authgate
    ports:
      - "8080:8080"
    volumes:
      - authgate-data:/app/data
    environment:
      - BASE_URL=https://auth.yourdomain.com
      - JWT_SECRET=${JWT_SECRET}
      - SESSION_SECRET=${SESSION_SECRET}
      - DATABASE_PATH=/app/data/oauth.db
      - DEFAULT_ADMIN_PASSWORD=${DEFAULT_ADMIN_PASSWORD}
      - ENABLE_RATE_LIMIT=true
      - ENABLE_AUDIT_LOGGING=true
    restart: unless-stopped
    healthcheck:
      test:
        [
          "CMD",
          "wget",
          "--no-verbose",
          "--tries=1",
          "--spider",
          "http://localhost:8080/health",
        ]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

volumes:
  authgate-data:
```

Create `.env` file:

```bash
JWT_SECRET=<generated-secret>
SESSION_SECRET=<generated-secret>
DEFAULT_ADMIN_PASSWORD=<your-password>
```

Deploy:

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Update and restart
docker-compose pull
docker-compose up -d
```

---

## Reverse Proxy Setup (Nginx)

### Prerequisites

- Nginx installed
- SSL certificate (via Let's Encrypt or other CA)
- DNS A record pointing to your server

### Nginx Configuration

Create `/etc/nginx/sites-available/authgate`:

```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=authgate_limit:10m rate=10r/s;

# Upstream backend
upstream authgate_backend {
    server localhost:8080;
    keepalive 32;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name auth.yourdomain.com;

    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting
    limit_req zone=authgate_limit burst=20 nodelay;

    # Logging
    access_log /var/log/nginx/authgate_access.log;
    error_log /var/log/nginx/authgate_error.log;

    # Proxy to AuthGate
    location / {
        proxy_pass http://authgate_backend;
        proxy_http_version 1.1;

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;

        # Keep-alive
        proxy_set_header Connection "";
    }

    # Health check endpoint (no rate limit)
    location /health {
        proxy_pass http://authgate_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        access_log off;
    }
}
```

### Enable Configuration

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/authgate /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### Obtain SSL Certificate (Let's Encrypt)

```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d auth.yourdomain.com

# Auto-renewal is configured by default
# Test renewal:
sudo certbot renew --dry-run
```

---

## Cloud Platform Deployment

### Fly.io

Fly.io provides a simple deployment experience with global edge network.

#### Prerequisites

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
flyctl auth login
```

#### Create `fly.toml`

```toml
app = "authgate"
primary_region = "sjc"

[build]
  dockerfile = "docker/Dockerfile"

[env]
  BASE_URL = "https://authgate.fly.dev"
  ENABLE_RATE_LIMIT = "true"
  ENABLE_AUDIT_LOGGING = "true"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 1

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256

[mounts]
  source = "authgate_data"
  destination = "/app/data"
```

#### Deploy

```bash
# Initialize app
flyctl launch

# Set secrets
flyctl secrets set JWT_SECRET=$(openssl rand -hex 32)
flyctl secrets set SESSION_SECRET=$(openssl rand -hex 32)
flyctl secrets set DEFAULT_ADMIN_PASSWORD=your-secure-password

# Create persistent volume
flyctl volumes create authgate_data --region sjc --size 1

# Deploy
flyctl deploy

# Check status
flyctl status

# View logs
flyctl logs

# Open in browser
flyctl open
```

---

## Production Checklist

Before going live, ensure you've completed:

### Security

- [ ] Changed `JWT_SECRET` to strong random value (32+ characters)
- [ ] Changed `SESSION_SECRET` to strong random value (32+ characters)
- [ ] Set secure `DEFAULT_ADMIN_PASSWORD` (or changed generated password)
- [ ] Enabled HTTPS (set `BASE_URL` to `https://...`)
- [ ] Configured firewall rules (only expose port 443)
- [ ] Set appropriate token expiration times
- [ ] Enabled rate limiting with appropriate limits
- [ ] Enabled audit logging with appropriate retention
- [ ] Reviewed [Security Guide](SECURITY.md)

### Infrastructure

- [ ] Set up regular database backups
- [ ] Configured log rotation
- [ ] Set up monitoring and alerting
- [ ] Configured health check endpoint
- [ ] Set up reverse proxy (Nginx/Caddy)
- [ ] Obtained SSL certificates
- [ ] Configured automatic SSL renewal

### Application

- [ ] Tested device authorization flow
- [ ] Tested OAuth third-party login (if enabled)
- [ ] Verified token refresh works correctly
- [ ] Tested session management and revocation
- [ ] Verified rate limiting is working
- [ ] Checked audit logs are being written
- [ ] Load tested with expected traffic

### Monitoring

- [ ] Set up health check monitoring (e.g., UptimeRobot, Pingdom)
- [ ] Configure log aggregation (e.g., Loki, ELK)
- [ ] Set up alerts for critical errors
- [ ] Monitor database size growth
- [ ] Track rate limit events
- [ ] Review audit logs regularly

---

**Next Steps:**

- [Monitoring Guide](MONITORING.md) - Set up monitoring and observability
- [Security Guide](SECURITY.md) - Production security best practices
- [Troubleshooting](TROUBLESHOOTING.md) - Common deployment issues
