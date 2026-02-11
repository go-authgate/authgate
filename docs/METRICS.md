# Prometheus Metrics

AuthGate exposes Prometheus metrics for monitoring OAuth flows, authentication, and HTTP requests.

## Quick Start

```bash
# Start the server
./bin/authgate server

# Access metrics endpoint
curl http://localhost:8080/metrics

# Filter for custom metrics
curl http://localhost:8080/metrics | grep -E "^(oauth|auth|http_request|session)"
```

## Metrics Endpoint

- **URL**: `http://localhost:8080/metrics`
- **Authentication**: Bearer Token (optional, configurable)
- **Format**: Prometheus text format
- **Update Frequency**: Real-time (counters/histograms), on-demand (gauges)

### Authentication

The metrics endpoint is **disabled by default** for security. Enable it and optionally configure Bearer Token authentication via environment variables in `.env`:

```bash
# Enable metrics endpoint (disabled by default)
METRICS_ENABLED=true                    # Default: false

# Optional: Configure Bearer Token
METRICS_TOKEN=your-secret-bearer-token  # Leave empty to disable auth

# See .env.example for full configuration
```

**Access examples:**

```bash
# Without authentication (default)
curl http://localhost:8080/metrics

# With Bearer Token enabled
curl -H "Authorization: Bearer your-secret-bearer-token" \
  http://localhost:8080/metrics

# Generate a strong random token (recommended for production)
openssl rand -base64 48
```

## Available Metrics

### OAuth Device Flow Metrics

| Metric                                             | Type      | Description                              | Labels                                        |
| -------------------------------------------------- | --------- | ---------------------------------------- | --------------------------------------------- |
| `oauth_device_codes_total`                         | Counter   | Total device codes generated             | `result` (success, error)                     |
| `oauth_device_codes_authorized_total`              | Counter   | Total device codes authorized by users   | -                                             |
| `oauth_device_code_validation_total`               | Counter   | Device code validation attempts          | `result` (success, expired, invalid, pending) |
| `oauth_device_codes_active`                        | Gauge     | Current number of active device codes    | -                                             |
| `oauth_device_codes_pending_authorization`         | Gauge     | Device codes awaiting user authorization | -                                             |
| `oauth_device_code_authorization_duration_seconds` | Histogram | Time for user to authorize device code   | -                                             |

### Token Metrics

| Metric                                    | Type      | Description               | Labels                                                                    |
| ----------------------------------------- | --------- | ------------------------- | ------------------------------------------------------------------------- |
| `oauth_tokens_issued_total`               | Counter   | Total tokens issued       | `token_type` (access, refresh), `grant_type` (device_code, refresh_token) |
| `oauth_tokens_revoked_total`              | Counter   | Total tokens revoked      | `reason` (user_request, admin, rotation, security)                        |
| `oauth_tokens_refreshed_total`            | Counter   | Token refresh attempts    | `result` (success, error)                                                 |
| `oauth_token_validation_total`            | Counter   | Token validation attempts | `result` (valid, invalid, expired)                                        |
| `oauth_tokens_active`                     | Gauge     | Current active tokens     | `token_type` (access, refresh)                                            |
| `oauth_token_generation_duration_seconds` | Histogram | Token generation time     | `provider` (local, http_api)                                              |
| `oauth_token_validation_duration_seconds` | Histogram | Token validation time     | `provider` (local, http_api)                                              |

### Authentication Metrics

| Metric                               | Type      | Description                   | Labels                                                                                 |
| ------------------------------------ | --------- | ----------------------------- | -------------------------------------------------------------------------------------- |
| `auth_attempts_total`                | Counter   | Total authentication attempts | `method` (local, http_api, oauth), `result` (success, failure)                         |
| `auth_login_total`                   | Counter   | Total login attempts          | `auth_source` (local, http_api, microsoft, github, gitea), `result` (success, failure) |
| `auth_logout_total`                  | Counter   | Total logouts                 | -                                                                                      |
| `auth_oauth_callback_total`          | Counter   | OAuth callback attempts       | `provider` (microsoft, github, gitea), `result` (success, error)                       |
| `auth_login_duration_seconds`        | Histogram | Login completion time         | `method` (local, http_api, oauth)                                                      |
| `auth_external_api_duration_seconds` | Histogram | External API auth call time   | `provider` (http_api)                                                                  |

### Session Metrics

| Metric                       | Type      | Description                | Labels                                                         |
| ---------------------------- | --------- | -------------------------- | -------------------------------------------------------------- |
| `sessions_active`            | Gauge     | Current active sessions    | -                                                              |
| `sessions_created_total`     | Counter   | Total sessions created     | -                                                              |
| `sessions_expired_total`     | Counter   | Total sessions expired     | `reason` (timeout, idle_timeout, logout, fingerprint_mismatch) |
| `sessions_invalidated_total` | Counter   | Total sessions invalidated | `reason` (security, admin)                                     |
| `session_duration_seconds`   | Histogram | Session duration           | -                                                              |

### HTTP Request Metrics

| Metric                          | Type      | Description                | Labels                     |
| ------------------------------- | --------- | -------------------------- | -------------------------- |
| `http_requests_total`           | Counter   | Total HTTP requests        | `method`, `path`, `status` |
| `http_request_duration_seconds` | Histogram | HTTP request latency       | `method`, `path`           |
| `http_requests_in_flight`       | Gauge     | Current in-flight requests | -                          |

## Prometheus Configuration

### Without Authentication

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "authgate"
    static_configs:
      - targets: ["localhost:8080"]
    metrics_path: "/metrics"
    scrape_interval: 15s
```

### With Bearer Token Authentication

When `METRICS_TOKEN` is configured:

```yaml
scrape_configs:
  - job_name: "authgate"
    static_configs:
      - targets: ["localhost:8080"]
    metrics_path: "/metrics"
    scrape_interval: 15s
    authorization:
      type: Bearer
      credentials: your-secret-bearer-token
```

Or use a credentials file for better security (recommended):

```yaml
scrape_configs:
  - job_name: "authgate"
    static_configs:
      - targets: ["localhost:8080"]
    metrics_path: "/metrics"
    scrape_interval: 15s
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/authgate_token.txt
```

Create the token file:

```bash
# Generate and save token
openssl rand -base64 48 > /etc/prometheus/authgate_token.txt
chmod 600 /etc/prometheus/authgate_token.txt
chown prometheus:prometheus /etc/prometheus/authgate_token.txt
```

## Grafana Dashboard Queries

### Request Rate by Endpoint

```promql
rate(http_requests_total[5m])
```

### Error Rate (5xx responses)

```promql
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])
```

### P95 Latency

```promql
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

### Active Device Codes

```promql
oauth_device_codes_active
```

### Token Issuance Rate

```promql
rate(oauth_tokens_issued_total[5m])
```

### Failed Authentication Rate

```promql
rate(auth_login_total{result="failure"}[5m])
```

### Average Session Duration

```promql
rate(session_duration_seconds_sum[5m]) / rate(session_duration_seconds_count[5m])
```

### Device Code Authorization Time (P99)

```promql
histogram_quantile(0.99, rate(oauth_device_code_authorization_duration_seconds_bucket[5m]))
```

## Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: authgate_alerts
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }}"

      - alert: HighFailedLoginRate
        expr: rate(auth_login_total{result="failure"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High failed login rate"
          description: "{{ $value }} failed logins per second"

      - alert: SlowTokenGeneration
        expr: histogram_quantile(0.95, rate(oauth_token_generation_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow token generation"
          description: "P95 token generation time is {{ $value }}s"
```

## Implementation Status

### ✅ Completed (Core Infrastructure)

- [x] Metrics initialization with singleton pattern
- [x] `/metrics` endpoint registration
- [x] HTTP request metrics (automatic via middleware)
- [x] All metric definitions and helper methods
- [x] Unit tests (79.3% coverage)
- [x] Integration with main.go

### ⚠️ Pending (Service Integration)

To complete metrics integration, the following services need to be updated to record metrics:

- [ ] **DeviceService**: Record device code generation, authorization, validation
- [ ] **TokenService**: Record token issuance, refresh, revocation, validation
- [ ] **AuthHandler**: Record login attempts, logout, session creation
- [ ] **OAuthHandler**: Record OAuth callbacks
- [ ] **Periodic Updates**: Background job to update gauge metrics (active tokens, sessions, device codes)

See [internal/metrics/INTEGRATION.md](../internal/metrics/INTEGRATION.md) for detailed integration examples.

## Security Considerations

### Production Deployment

The `/metrics` endpoint now supports built-in authentication via Bearer Token. Choose the appropriate security level for your deployment:

#### Option 1: Built-in Bearer Token (Recommended for Most Cases)

Enable authentication via environment variables:

```bash
METRICS_ENABLED=true
METRICS_TOKEN=$(openssl rand -base64 48)
```

**Pros:**

- Simple to configure - only one token needed
- Industry standard for API authentication
- Works with Prometheus `authorization` configuration
- Constant-time token comparison prevents timing attacks
- No username needed - cleaner than Basic Auth

**Cons:**

- Token passed in headers (use HTTPS in production)
- Single shared token for all Prometheus instances

#### Option 2: Network-Level Restriction

If you prefer, restrict access via firewall or reverse proxy:

1. **Disable built-in auth** (leave `METRICS_TOKEN` empty)
2. **Network policies**: Allow only Prometheus server IP

```nginx
# Nginx example - restrict to internal IPs
location /metrics {
    allow 10.0.0.0/8;     # Internal network
    allow 172.16.0.0/12;  # Docker network
    deny all;
    proxy_pass http://authgate:8080;
}
```

3. **Use Network Policies**: In Kubernetes, restrict access via NetworkPolicy:

   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: authgate-metrics
   spec:
     podSelector:
       matchLabels:
         app: authgate
     ingress:
       - from:
           - namespaceSelector:
               matchLabels:
                 name: monitoring
         ports:
           - protocol: TCP
             port: 8080
   ```

#### Best Practices

1. **Always use HTTPS in production** to protect token in transit
2. **Use strong, randomly generated tokens** (at least 32 characters, recommend 48+ bytes base64-encoded)
3. **Rotate tokens periodically** (store in secrets management system like Vault, AWS Secrets Manager)
4. **Enable both authentication AND network restrictions** for defense in depth
5. **Monitor failed authentication attempts** via application logs
6. **Use Prometheus credentials_file** instead of hardcoding tokens in config

### Label Cardinality

**Important**: Never use high-cardinality values as labels (user IDs, tokens, IP addresses) as this can cause memory issues:

```promql
# ❌ BAD - Unbounded cardinality
http_requests_total{user_id="12345"}

# ✅ GOOD - Bounded set of values
http_requests_total{path="/oauth/token"}
```

Current implementation uses only low-cardinality labels (method, status, provider, etc.).

## Troubleshooting

### Metrics Not Appearing

1. Check server logs for initialization:

   ```
   Prometheus metrics initialized
   ```

2. Verify endpoint is accessible:

   ```bash
   curl http://localhost:8080/metrics
   ```

3. Check for metric registration errors in logs

### Duplicate Metrics Error

If you see "duplicate metrics collector registration", this indicates the metrics are being initialized multiple times. This is prevented by using `sync.Once` in production code, but may occur in tests.

### High Memory Usage

If Prometheus memory usage is high:

1. Check for high-cardinality labels
2. Reduce scrape frequency
3. Adjust Prometheus retention settings

## Performance Impact

- **HTTP Middleware**: < 1ms overhead per request
- **Metric Recording**: < 0.1ms per operation
- **Memory Usage**: ~1-2MB for metric storage
- **CPU Impact**: < 1% under normal load

## Related Documentation

- [MONITORING.md](MONITORING.md) - Monitoring best practices
- [internal/metrics/INTEGRATION.md](../internal/metrics/INTEGRATION.md) - Service integration guide
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Dashboards](https://grafana.com/docs/)
