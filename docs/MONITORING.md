# Monitoring and Observability

This guide covers monitoring, health checks, logging, and audit trails for AuthGate.

## Table of Contents

- [Health Check Endpoint](#health-check-endpoint)
- [Monitoring Best Practices](#monitoring-best-practices)
- [Audit Logging](#audit-logging)
- [Logging Configuration](#logging-configuration)
- [Alerting](#alerting)

---

## Health Check Endpoint

AuthGate provides a health check endpoint for monitoring service availability and database connectivity.

### Basic Usage

```bash
# Check service health
curl http://localhost:8080/health

# Response (healthy)
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2026-02-08T10:00:00Z"
}

# Response (unhealthy - database issue)
{
  "status": "unhealthy",
  "database": "disconnected",
  "error": "database connection failed",
  "timestamp": "2026-02-08T10:00:00Z"
}
```

### Health Check Details

- **Endpoint**: `GET /health`
- **Authentication**: Not required
- **HTTP Status**:
  - `200 OK` - Service and database are healthy
  - `503 Service Unavailable` - Database connection failed
- **Database Test**: Performs a `PING` operation to verify connectivity
- **Response Time**: < 100ms typically

### Integration with Monitoring Tools

**Docker Compose:**

```yaml
healthcheck:
  test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
  interval: 30s
  timeout: 3s
  retries: 3
  start_period: 5s
```

**Kubernetes:**

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
  timeoutSeconds: 3
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

**UptimeRobot / Pingdom:**

- Monitor URL: `https://auth.yourdomain.com/health`
- Check interval: 5 minutes
- Expected status: 200
- Alert on: Status != 200 or timeout

---

## Monitoring Best Practices

### Key Metrics to Monitor

#### Service Health

- ✅ **Health check endpoint availability** (target: 99.9% uptime)
- ✅ **HTTP response times** (target: p95 < 200ms, p99 < 500ms)
- ✅ **Error rate** (target: < 0.1% of requests)

#### Database

- 📊 **Database file size growth** (SQLite)
- 📊 **Connection pool utilization** (PostgreSQL)
- 📊 **Query execution time** (target: < 50ms average)
- 📊 **Database lock contention** (SQLite)

#### Application Metrics

- 🔐 **Active device codes count** (track pending authorizations)
- 🔐 **Issued tokens per hour** (baseline: establish normal patterns)
- 🔐 **Active sessions count** (per user and total)
- 🔐 **Failed login attempts** (baseline: < 5% of total logins)
- 🔐 **Token refresh rate** (track refresh token usage)

#### Security Metrics

- 🚨 **Rate limit exceeded events** (potential attacks)
- 🚨 **Failed authentication attempts per IP** (brute force detection)
- 🚨 **Suspicious activity events** (from audit logs)
- 🚨 **Critical/Error severity audit events**

#### Audit Log Metrics

- 📈 **Audit events per hour** (establish baseline)
- 📈 **Critical severity events** (alert immediately)
- 📈 **Failed authentication rate** (security monitoring)
- 📈 **Token revocation frequency** (user security awareness)

### Recommended Monitoring Stack

**Option 1: Prometheus + Grafana**

```bash
# Add Prometheus metrics endpoint (future enhancement)
# For now, parse logs and health checks
```

**Option 2: Cloud-Native (Fly.io, AWS CloudWatch)**

- Use platform-provided metrics
- Monitor health check endpoint
- Set up log aggregation

**Option 3: Simple Monitoring (Small Deployments)**

- UptimeRobot for health checks
- Papertrail/Logtail for log aggregation
- Weekly manual audit log review

---

## Audit Logging

AuthGate includes a comprehensive audit logging system that tracks all critical operations and security events.

### Key Features

- **Comprehensive Event Coverage**: Authentication, device authorization, token operations, admin actions, security events
- **Asynchronous Processing**: Non-blocking batch writes (every 1 second or 100 records) for minimal performance impact
- **Automatic Data Masking**: Sensitive fields (passwords, tokens, secrets) are automatically redacted
- **Flexible Filtering**: Search and filter by event type, severity, actor, resource, time range, success/failure
- **Web Interface**: View, search, filter, and export audit logs through admin panel
- **CSV Export**: Export filtered logs for external analysis or compliance reporting
- **Statistics Dashboard**: View event counts by type, severity, and success rate
- **Automatic Cleanup**: Configurable retention period with automatic deletion of old logs
- **Graceful Shutdown**: Ensures all buffered logs are written before server stops

### Configuration

Configure audit logging via environment variables in `.env`:

```bash
# Audit Logging
ENABLE_AUDIT_LOGGING=true                # Enable audit logging (default: true)
AUDIT_LOG_RETENTION=2160h               # Retention period: 90 days (default)
AUDIT_LOG_BUFFER_SIZE=1000              # Async buffer size (default: 1000)
AUDIT_LOG_CLEANUP_INTERVAL=24h          # Cleanup frequency (default: 24h)
```

### Configuration Options

- **ENABLE_AUDIT_LOGGING**: Master switch (default: `true`)
- **AUDIT_LOG_RETENTION**: How long to keep logs (default: `90 days` = `2160h`)
- **AUDIT_LOG_BUFFER_SIZE**: Async buffer size (default: `1000`)
- **AUDIT_LOG_CLEANUP_INTERVAL**: Cleanup job frequency (default: `24h`)

### Performance Notes

- Audit events written asynchronously (non-blocking)
- Batch writes every 1 second or 100 records
- Buffer overflow drops events with warning (rare)
- Typical overhead: < 1% CPU, < 10 MB memory for 100k events

### Web Interface

Access audit logs through the admin panel:

**Endpoints:**

- `GET /admin/audit` - View audit logs (HTML, requires admin login)
- `GET /admin/audit/export` - Export filtered logs as CSV
- `GET /admin/audit/api` - JSON API for programmatic access
- `GET /admin/audit/api/stats` - Statistics and event counts

**Web UI Features:**

- **Search**: Full-text search across action, resource name, actor username
- **Filters**: Event type, severity, success/failure, actor IP, resource type, time range
- **Pagination**: Configurable page size (default: 20 records per page)
- **CSV Export**: Download filtered results for Excel/spreadsheet analysis
- **Real-time Updates**: New events appear after page refresh

### Event Types

**Authentication Events:**

- `AUTHENTICATION_SUCCESS` - User successfully logged in
- `AUTHENTICATION_FAILURE` - Failed login attempt
- `LOGOUT` - User logged out
- `OAUTH_AUTHENTICATION` - OAuth provider authentication

**Device Authorization Events:**

- `DEVICE_CODE_GENERATED` - Device code created for CLI/device
- `DEVICE_CODE_AUTHORIZED` - User authorized device in browser

**Token Events:**

- `ACCESS_TOKEN_ISSUED` - Access token generated
- `REFRESH_TOKEN_ISSUED` - Refresh token generated
- `TOKEN_REFRESHED` - Access token refreshed
- `TOKEN_REVOKED` - Token permanently revoked
- `TOKEN_DISABLED` - Token temporarily disabled
- `TOKEN_ENABLED` - Disabled token re-enabled

**Admin Operations:**

- `CLIENT_CREATED` - OAuth client created
- `CLIENT_UPDATED` - OAuth client modified
- `CLIENT_DELETED` - OAuth client removed
- `CLIENT_SECRET_REGENERATED` - Client secret rotated

**Security Events:**

- `RATE_LIMIT_EXCEEDED` - Request blocked by rate limiter
- `SUSPICIOUS_ACTIVITY` - Anomalous behavior detected

### Severity Levels

- `INFO` - Normal operations (login, token issuance)
- `WARNING` - Potentially concerning (failed auth, rate limit)
- `ERROR` - Operation failures (token refresh failure)
- `CRITICAL` - Security incidents (suspicious activity)

### Best Practices

**Security & Compliance:**

1. **Monitor Critical Events**: Set up alerts for `CRITICAL` and `ERROR` severity
2. **Regular Review**: Weekly review of `AUTHENTICATION_FAILURE` and `RATE_LIMIT_EXCEEDED`
3. **Compliance Exports**: Use CSV export for audits (SOC 2, ISO 27001, GDPR)
4. **Retention Policy**: Adjust based on compliance (90 days typical, some require 1+ year)

**Performance Optimization:**

1. **Database Indexes**: Audit logs include indexes on time, type, actor, severity
2. **Regular Cleanup**: Enable automatic cleanup to prevent database bloat
3. **Monitor Buffer**: Watch for "buffer full" warnings in logs

**Operational:**

1. **Backup Strategy**: Include audit logs in database backups
2. **Cold Storage**: Consider archiving old logs for long-term retention
3. **Access Control**: Audit viewing requires admin role

### Example Queries

**View failed logins in last 24 hours:**

```bash
curl -s "http://localhost:8080/admin/audit/api?event_type=AUTHENTICATION_FAILURE&since=24h" \
  -H "Cookie: session=..." | jq .
```

**Export all critical events as CSV:**

```bash
curl "http://localhost:8080/admin/audit/export?severity=CRITICAL" \
  -H "Cookie: session=..." -o critical-events.csv
```

**Get statistics:**

```bash
curl -s "http://localhost:8080/admin/audit/api/stats" \
  -H "Cookie: session=..." | jq .
```

---

## Logging Configuration

### Application Logs

AuthGate uses Gin's built-in logger for HTTP request logging:

```
[GIN] 2026/02/08 - 10:00:00 | 200 |    1.234ms |  192.168.1.1 | GET  "/health"
[GIN] 2026/02/08 - 10:00:01 | 201 |   12.345ms |  192.168.1.2 | POST "/oauth/device/code"
```

### Systemd Journal (Linux)

```bash
# View all logs
sudo journalctl -u authgate -f

# View logs from last hour
sudo journalctl -u authgate --since "1 hour ago"

# View only errors
sudo journalctl -u authgate -p err

# Export to file
sudo journalctl -u authgate --since "2026-02-01" > authgate.log
```

### Docker Logs

```bash
# Follow logs
docker logs -f authgate

# Last 100 lines
docker logs --tail 100 authgate

# Since timestamp
docker logs --since "2026-02-08T10:00:00" authgate
```

### Log Aggregation

**Loki (Grafana) Example:**

```yaml
# promtail-config.yml
clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: authgate
    static_configs:
      - targets:
          - localhost
        labels:
          job: authgate
          __path__: /var/log/authgate/*.log
```

**Papertrail Example:**

```bash
# Forward logs to Papertrail
sudo journalctl -u authgate -f | \
  nc logs.papertrailapp.com <your-port>
```

---

## Alerting

### Critical Alerts (Immediate Response)

- 🚨 Health check fails for > 2 minutes
- 🚨 Error rate > 5% for > 5 minutes
- 🚨 Database connection failures
- 🚨 Critical severity audit events
- 🚨 > 100 failed login attempts from single IP in 10 minutes

### Warning Alerts (Review Within 1 Hour)

- ⚠️ Health check intermittent failures
- ⚠️ Database size > 80% of available space
- ⚠️ Rate limit exceeded > 1000 times per hour
- ⚠️ Error severity audit events
- ⚠️ Unusual spike in authentication failures

### Info Alerts (Daily Review)

- ℹ️ Daily summary of audit events
- ℹ️ Token issuance rate trends
- ℹ️ Active session count
- ℹ️ Database backup completion

### Example Alert Configuration (UptimeRobot)

```
Alert Name: AuthGate Health Check
Monitor Type: HTTP(s)
URL: https://auth.yourdomain.com/health
Interval: 5 minutes
Alert Contacts: email, slack, pagerduty
```

---

**Next Steps:**

- [Security Guide](SECURITY.md) - Production security best practices
- [Troubleshooting](TROUBLESHOOTING.md) - Debug common issues
- [Configuration Guide](CONFIGURATION.md) - Configure audit logging
