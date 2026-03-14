# Rate Limiting Guide

AuthGate provides built-in rate limiting to protect against brute force attacks and API abuse. This guide covers configuration and deployment scenarios.

## Overview

Rate limiting is **enabled by default** and uses an in-memory store suitable for single-instance deployments. For multi-pod/multi-instance deployments, Redis-backed rate limiting ensures consistent rate limits across all instances.

## Storage Backends

### Memory Store (Default)

**Best for:**

- Single instance deployments
- Development environments
- Simple deployments without scaling requirements

**Configuration:**

```bash
ENABLE_RATE_LIMIT=true
RATE_LIMIT_STORE=memory  # or omit this line (default)
```

**Limitations:**

- Each instance has independent rate limits
- Example: With 3 pods and `LOGIN_RATE_LIMIT=5`, users can make 15 requests/minute (5 per pod)
- Not suitable for load-balanced deployments

### Redis Store

**Best for:**

- Multi-pod Kubernetes deployments
- Load-balanced instances
- Production environments with horizontal scaling

**Configuration:**

```bash
ENABLE_RATE_LIMIT=true
RATE_LIMIT_STORE=redis
REDIS_ADDR=redis-service:6379
REDIS_PASSWORD=your-redis-password  # Optional
REDIS_DB=0
```

**Benefits:**

- Shared rate limit state across all pods
- Accurate global rate limiting (5 req/min = 5 total across all pods)
- Survives pod restarts (Redis persists state)

## Rate Limit Configuration

### Default Limits

| Endpoint             | Requests/Minute | Purpose                              |
| -------------------- | --------------- | ------------------------------------ |
| `/login`             | 5               | Prevent password brute force         |
| `/oauth/device/code` | 10              | Prevent device code spam             |
| `/oauth/token`       | 20              | Allow polling while preventing abuse |
| `/device/verify`     | 10              | Prevent user code guessing           |
| `/oauth/register`   | 5               | Prevent registration spam            |
| `/oauth/introspect` | 20              | Prevent client secret brute force    |

### Customizing Limits

Adjust limits via environment variables:

```bash
# More permissive (e.g., high-traffic API)
LOGIN_RATE_LIMIT=20
TOKEN_RATE_LIMIT=60

# More restrictive (e.g., security-critical)
LOGIN_RATE_LIMIT=3
DEVICE_VERIFY_RATE_LIMIT=5

# Dynamic client registration and introspection
DYNAMIC_CLIENT_REGISTRATION_RATE_LIMIT=10
INTROSPECT_RATE_LIMIT=50
```

### Disabling Rate Limiting

**Not recommended for production:**

```bash
ENABLE_RATE_LIMIT=false
```

## Deployment Scenarios

### Scenario 1: Single Instance (Docker)

```yaml
# docker-compose.yml
services:
  authgate:
    image: authgate:latest
    environment:
      - ENABLE_RATE_LIMIT=true
      - RATE_LIMIT_STORE=memory # Default
      - LOGIN_RATE_LIMIT=5
```

### Scenario 2: Kubernetes with Redis

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authgate
spec:
  replicas: 3 # Multiple pods
  template:
    spec:
      containers:
        - name: authgate
          image: authgate:latest
          env:
            - name: ENABLE_RATE_LIMIT
              value: "true"
            - name: RATE_LIMIT_STORE
              value: "redis"
            - name: REDIS_ADDR
              value: "redis-service:6379"
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: redis-secret
                  key: password
---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
spec:
  selector:
    app: redis
  ports:
    - port: 6379
      targetPort: 6379
```

### Scenario 3: Load Balanced (Nginx + Redis)

```nginx
# nginx.conf
upstream authgate {
    server authgate-1:8080;
    server authgate-2:8080;
    server authgate-3:8080;
}

server {
    listen 80;
    location / {
        proxy_pass http://authgate;
    }
}
```

```bash
# Each AuthGate instance
ENABLE_RATE_LIMIT=true
RATE_LIMIT_STORE=redis
REDIS_ADDR=redis.example.com:6379
```

## Redis Setup

### Local Development

```bash
# Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Environment
REDIS_ADDR=localhost:6379
```

### Production (Redis Cluster)

```bash
REDIS_ADDR=redis-cluster.prod.example.com:6379
REDIS_PASSWORD=your-strong-password
REDIS_DB=1  # Use dedicated database
```

### High Availability (Sentinel)

```bash
# Use Redis Sentinel for HA
REDIS_ADDR=sentinel-1:26379,sentinel-2:26379,sentinel-3:26379
REDIS_PASSWORD=your-password
```

## Monitoring

### Health Check

Rate limiting failures are logged:

```bash
# Check logs for rate limiting issues
docker logs authgate | grep -i "rate"
```

### Redis Connection

Verify Redis connectivity on startup:

```
2024/01/01 12:00:00 Rate limiting enabled (store: redis)
2024/01/01 12:00:00 Redis rate limiting configured: redis-service:6379 (DB: 0)
```

### Rate Limit Events

When a client is rate limited, a 429 response is returned:

```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests. Please try again later."
}
```

## Troubleshooting

### Issue: "Failed to connect to Redis"

**Cause:** Redis server unreachable or incorrect address

**Solution:**

1. Verify Redis is running: `redis-cli ping`
2. Check `REDIS_ADDR` configuration
3. Verify network connectivity
4. Check Redis password if authentication is enabled

### Issue: Rate limits not working across pods

**Cause:** Using memory store with multiple pods

**Solution:** Switch to Redis store:

```bash
RATE_LIMIT_STORE=redis
REDIS_ADDR=your-redis-service:6379
```

### Issue: Legitimate users getting rate limited

**Cause:** Limits too restrictive or shared IP (NAT/proxy)

**Solutions:**

1. Increase rate limits:

   ```bash
   LOGIN_RATE_LIMIT=10
   ```

2. Configure reverse proxy to preserve client IPs:

   ```nginx
   proxy_set_header X-Forwarded-For $remote_addr;
   ```

### Issue: Redis memory usage growing

**Cause:** Rate limiter keys accumulating

**Solution:** Verify cleanup is working:

```bash
# Check Redis keys
redis-cli KEYS "ratelimit:*"

# Set TTL on keys (automatic with limiter)
# Increase cleanup interval if needed
RATE_LIMIT_CLEANUP_INTERVAL=10m
```

## Best Practices

1. **Use Redis in production**: Always use Redis store for multi-instance deployments
2. **Monitor Redis health**: Set up Redis monitoring and alerting
3. **Test rate limits**: Verify limits with load testing before production
4. **Log rate limit events**: Monitor for unusual patterns
5. **Adjust based on traffic**: Start conservative, increase as needed
6. **Use Redis persistence**: Enable AOF or RDB for Redis durability
7. **Separate Redis instance**: Use dedicated Redis for rate limiting (optional)

## Performance Considerations

### Memory Store

- **Latency:** ~1ms (in-memory)
- **Throughput:** 10,000+ req/s per instance
- **Memory:** ~1KB per active IP

### Redis Store

- **Latency:** ~2-5ms (network + Redis)
- **Throughput:** 5,000+ req/s (depends on Redis)
- **Memory:** ~1KB per active IP (stored in Redis)

## Security Notes

- Rate limiting is **per IP address**
- Use `X-Forwarded-For` header when behind proxy/load balancer
- Consider additional WAF rules for sophisticated attacks
- Rate limiting is one layer; combine with other security measures
- Review logs regularly for attack patterns
- Adjust limits based on your threat model

## Example: Aggressive Rate Limiting

For high-security environments:

```bash
# Very restrictive limits
LOGIN_RATE_LIMIT=3                # 3 login attempts per minute
LOGIN_RATE_LIMIT_BURST=1          # No burst (memory store only)
DEVICE_CODE_RATE_LIMIT=5          # 5 device codes per minute
TOKEN_RATE_LIMIT=10               # 10 token requests per minute
DEVICE_VERIFY_RATE_LIMIT=5        # 5 verifications per minute

# Use Redis for consistent enforcement
RATE_LIMIT_STORE=redis
REDIS_ADDR=redis:6379
```

## Example: Permissive Rate Limiting

For internal APIs or development:

```bash
# More permissive limits
LOGIN_RATE_LIMIT=20               # 20 login attempts per minute
DEVICE_CODE_RATE_LIMIT=30         # 30 device codes per minute
TOKEN_RATE_LIMIT=60               # 60 token requests per minute (every second)
DEVICE_VERIFY_RATE_LIMIT=30       # 30 verifications per minute

# Memory store is fine for single instance
RATE_LIMIT_STORE=memory
```

## Migration Guide

### From Memory to Redis

1. Deploy Redis:

   ```bash
   kubectl apply -f redis-deployment.yaml
   ```

2. Update AuthGate configuration:

   ```bash
   RATE_LIMIT_STORE=redis
   REDIS_ADDR=redis-service:6379
   ```

3. Rolling restart (Kubernetes):

   ```bash
   kubectl rollout restart deployment/authgate
   ```

4. Verify:

   ```bash
   kubectl logs -f deployment/authgate | grep "Redis rate limiting configured"
   ```

## Further Reading

- [RFC 6585 - HTTP Status Code 429](https://tools.ietf.org/html/rfc6585)
- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [Redis Best Practices](https://redis.io/docs/management/optimization/)
- [Kubernetes Horizontal Pod Autoscaling](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/)
