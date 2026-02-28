# Performance Guide

This guide covers performance considerations, optimization tips, and scalability options for AuthGate.

## Table of Contents

- [Scalability](#scalability)
- [Performance Tips](#performance-tips)
- [Benchmarks](#benchmarks)
- [Database Optimization](#database-optimization)
- [Caching Strategies](#caching-strategies)
- [Load Testing](#load-testing)
- [Comparison with Other Solutions](#comparison-with-other-solutions)

---

## Scalability

### Current Architecture (SQLite)

**Suitable for:**

- Small to medium deployments (< 1000 concurrent devices)
- Single-instance deployments
- Development and testing
- Low-traffic production environments

**Limitations:**

- SQLite write locks can cause contention under heavy load
- Single file limits horizontal scaling
- No built-in replication
- Write-heavy workloads may experience bottlenecks

**Recommended Thresholds:**

- **Users**: < 10,000 active users
- **Devices**: < 1,000 concurrent devices
- **Requests**: < 100 req/sec sustained
- **Database Size**: < 1 GB (optimal performance)

### For High-Scale Deployments

AuthGate supports PostgreSQL natively for production deployments:

```bash
# .env configuration
DATABASE_DRIVER=postgres
DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=require"
```

**PostgreSQL Advantages:**

- ✅ **Better Concurrency**: Handles multiple simultaneous writes
- ✅ **Horizontal Scaling**: Read replicas for load distribution
- ✅ **Connection Pooling**: Efficient resource utilization
- ✅ **Advanced Indexing**: GiST, GIN indexes for complex queries
- ✅ **Replication**: Built-in streaming replication
- ✅ **No File Locks**: MVCC (Multi-Version Concurrency Control)

**Recommended for:**

- **Users**: > 10,000 active users
- **Devices**: > 1,000 concurrent devices
- **Requests**: > 100 req/sec sustained
- **Multi-pod deployments**: Kubernetes, cloud platforms

### Horizontal Scaling

**Single Instance (Up to 100 req/sec):**

```
┌─────────────┐
│  AuthGate   │
│  (SQLite)   │
└─────────────┘
```

**Load Balanced (Up to 1000 req/sec):**

```
         ┌─────────────┐
         │   Nginx     │
         │ (Round Robin)│
         └──────┬──────┘
                │
      ┌─────────┴─────────┐
      │                   │
┌─────▼─────┐       ┌─────▼─────┐
│ AuthGate  │       │ AuthGate  │
│   Pod 1   │       │   Pod 2   │
└─────┬─────┘       └─────┬─────┘
      │                   │
      └─────────┬─────────┘
                │
         ┌──────▼──────┐
         │ PostgreSQL  │
         │  (Primary)  │
         └─────────────┘
```

**High Availability (> 1000 req/sec):**

```
         ┌─────────────┐
         │   Nginx     │
         │   + Redis   │
         │(Rate Limit) │
         └──────┬──────┘
                │
      ┌─────────┴─────────┬─────────────┐
      │                   │             │
┌─────▼─────┐       ┌─────▼─────┐ ┌────▼─────┐
│ AuthGate  │       │ AuthGate  │ │AuthGate  │
│   Pod 1   │       │   Pod 2   │ │  Pod 3   │
└─────┬─────┘       └─────┬─────┘ └────┬─────┘
      │                   │             │
      └─────────┬─────────┴─────────────┘
                │
         ┌──────▼──────┐       ┌──────────────┐
         │ PostgreSQL  │◄──────│  PostgreSQL  │
         │  (Primary)  │       │  (Replica)   │
         └─────────────┘       └──────────────┘
```

---

## Performance Tips

### 1. Enable SQLite WAL Mode

Write-Ahead Logging improves concurrent read performance:

```bash
# Enable WAL mode
sqlite3 oauth.db "PRAGMA journal_mode=WAL;"

# Verify
sqlite3 oauth.db "PRAGMA journal_mode;"
# Should return: wal
```

**Benefits:**

- Readers don't block writers
- Writers don't block readers
- Better concurrency for read-heavy workloads

### 2. Add Database Indexes

Create indexes on frequently queried columns:

```sql
-- Device codes
CREATE INDEX IF NOT EXISTS idx_device_codes_device_code ON device_codes(device_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_client_id ON device_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);

-- Access tokens
CREATE INDEX IF NOT EXISTS idx_access_tokens_token ON access_tokens(token);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_status ON access_tokens(status);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);

-- Users
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id);
```

### 3. Implement Connection Pooling (PostgreSQL)

Configure GORM connection pool settings:

```go
// In store/sqlite.go or store/postgres.go
sqlDB, err := db.DB()
if err != nil {
    return nil, err
}

// Set connection pool settings
sqlDB.SetMaxIdleConns(10)           // Idle connections in pool
sqlDB.SetMaxOpenConns(100)          // Max open connections
sqlDB.SetConnMaxLifetime(time.Hour) // Max connection lifetime
```

**Recommended Settings:**

- **MaxIdleConns**: 10-20 (for moderate traffic)
- **MaxOpenConns**: 50-100 (adjust based on load)
- **ConnMaxLifetime**: 1 hour (prevents stale connections)

### 4. Use Redis for Session Storage

Replace cookie-based sessions with Redis for multi-pod deployments:

```go
// In main.go (example - requires implementation)
import "github.com/gin-contrib/sessions/redis"

store, _ := redis.NewStore(10, "tcp", "localhost:6379", "", []byte(cfg.SessionSecret))
router.Use(sessions.Sessions("authgate-session", store))
```

**Benefits:**

- Shared session state across pods
- Better scalability
- Configurable TTL
- Persistence across restarts

### 5. Add Caching Layer for Token Validation

Cache valid tokens to reduce database queries:

```go
// Pseudo-code example
func (s *TokenService) ValidateToken(tokenString string) (*TokenValidationResult, error) {
    // Check cache first
    if cachedResult := s.cache.Get(tokenString); cachedResult != nil {
        return cachedResult, nil
    }

    // Validate token
    result, err := s.provider.ValidateToken(tokenString)
    if err != nil {
        return nil, err
    }

    // Cache valid tokens (with expiration)
    s.cache.Set(tokenString, result, result.ExpiresAt)
    return result, nil
}
```

### 6. Clean Up Expired Records Regularly

Remove expired device codes and tokens:

```sql
-- Delete expired device codes (older than 1 hour)
DELETE FROM device_codes
WHERE expires_at < datetime('now', '-1 hour');

-- Delete expired access tokens
DELETE FROM access_tokens
WHERE expires_at < datetime('now')
  AND status = 'revoked';

-- Vacuum database to reclaim space (SQLite)
VACUUM;
```

**Automated Cleanup (Cron Job):**

```bash
# /etc/cron.daily/authgate-cleanup
#!/bin/bash
sqlite3 /var/lib/authgate/oauth.db <<EOF
DELETE FROM device_codes WHERE expires_at < datetime('now', '-1 hour');
DELETE FROM access_tokens WHERE expires_at < datetime('now') AND status = 'revoked';
VACUUM;
EOF
```

### 7. Optimize Session Management Queries

Session management uses batch queries to avoid N+1 problems:

```go
// Good: Batch query with WHERE IN
tokenIDs := []string{"id1", "id2", "id3"}
db.Preload("User").Preload("OAuthClient").Where("id IN ?", tokenIDs).Find(&tokens)

// Bad: N+1 query
for _, tokenID := range tokenIDs {
    db.Preload("User").Preload("OAuthClient").First(&token, tokenID)
}
```

### 8. Enable HTTP/2

Configure Nginx for HTTP/2 support:

```nginx
server {
    listen 443 ssl http2;  # Enable HTTP/2
    # ... rest of configuration
}
```

**Benefits:**

- Multiplexing (multiple requests over single connection)
- Header compression
- Server push support
- Better performance for modern clients

---

## Benchmarks

### Reference Benchmarks

**Hardware:** 2-core CPU, 4GB RAM, SSD

**Test Scenario:** 100 concurrent device authorization flows

| Metric               | SQLite | PostgreSQL |
| -------------------- | ------ | ---------- |
| Requests/sec         | ~500   | ~2000      |
| Avg Response Time    | 20ms   | 5ms        |
| P95 Response Time    | 50ms   | 15ms       |
| P99 Response Time    | 100ms  | 30ms       |
| Database Size (1000) | 2MB    | 5MB        |
| CPU Usage            | 15%    | 10%        |
| Memory Usage         | 50MB   | 80MB       |

### Endpoint-Specific Performance

| Endpoint             | Avg Latency | P95 Latency | Notes                       |
| -------------------- | ----------- | ----------- | --------------------------- |
| GET /health          | 1ms         | 3ms         | Minimal database query      |
| POST /login          | 150ms       | 300ms       | bcrypt hashing overhead     |
| POST /device/code    | 10ms        | 25ms        | UUID generation + DB insert |
| POST /oauth/token    | 15ms        | 35ms        | JWT generation + DB query   |
| GET /oauth/tokeninfo | 8ms         | 20ms        | JWT verification only       |
| POST /device/verify  | 12ms        | 30ms        | DB update + session check   |

### Bottlenecks

**Common Performance Bottlenecks:**

1. **bcrypt Password Hashing** (150-200ms)
   - Use appropriate cost factor (default: 10)
   - Consider external authentication API for high-scale

2. **SQLite Write Locks** (contention at >50 concurrent writes)
   - Solution: Migrate to PostgreSQL

3. **JWT Generation** (minimal, but accumulates)
   - Consider external token provider for custom needs

4. **Session Cookie Size** (affects request overhead)
   - Keep session data minimal
   - Consider Redis for large session data

---

## Database Optimization

### SQLite Optimization

```sql
-- Analyze database for query optimizer
ANALYZE;

-- Set optimal page size (default: 4096)
PRAGMA page_size = 4096;

-- Enable memory-mapped I/O
PRAGMA mmap_size = 268435456; -- 256MB

-- Set cache size
PRAGMA cache_size = -64000; -- 64MB

-- Synchronous mode (trade-off: speed vs safety)
PRAGMA synchronous = NORMAL; -- Faster than FULL, safer than OFF
```

### PostgreSQL Optimization

```sql
-- Update statistics for query planner
ANALYZE;

-- Create partial indexes for common queries
CREATE INDEX idx_active_tokens ON access_tokens(user_id)
WHERE status = 'active' AND expires_at > NOW();

-- Create composite indexes
CREATE INDEX idx_device_codes_lookup ON device_codes(client_id, expires_at);

-- Enable query logging for slow queries
ALTER DATABASE authgate SET log_min_duration_statement = 1000; -- Log queries > 1s
```

**postgresql.conf tuning:**

```ini
# Memory settings
shared_buffers = 256MB              # 25% of RAM
effective_cache_size = 1GB          # 50% of RAM
work_mem = 16MB                     # Per-operation memory

# Connection settings
max_connections = 100               # Adjust based on load
shared_preload_libraries = 'pg_stat_statements' # Query stats
```

---

## Caching Strategies

### Token Validation Caching

Use Redis for caching validated tokens:

```go
// Pseudo-code
type CachedTokenInfo struct {
    Valid     bool
    UserID    string
    ClientID  string
    Scopes    string
    ExpiresAt time.Time
}

func (s *TokenService) ValidateTokenCached(token string) (*CachedTokenInfo, error) {
    // Check Redis cache
    key := fmt.Sprintf("token:valid:%s", hash(token))
    if cached := redis.Get(key); cached != nil {
        return cached, nil
    }

    // Validate and cache
    result, err := s.ValidateToken(token)
    if err == nil && result.Valid {
        ttl := time.Until(result.ExpiresAt)
        redis.Set(key, result, ttl)
    }

    return result, err
}
```

### User Object Caching (Built-in)

`GetUserByID` is called on **every protected request** (once by `RequireAuth`, once more by `RequireAdmin`). AuthGate ships with a built-in user cache that absorbs this DB load automatically — no additional configuration required.

**How it works:**

- First request: DB lookup, result written to cache
- Subsequent requests: served from cache, zero DB queries
- Cache invalidated automatically after writes (e.g., OAuth profile sync)
- `USER_CACHE_TTL` controls how long a cached user entry is valid (default: 5 minutes)

**Deployment guidance:**

| Deployment                | Recommended backend | Config                        |
| ------------------------- | ------------------- | ----------------------------- |
| Single instance           | `memory` (default)  | No changes needed             |
| 2–5 pods                  | `redis`             | `USER_CACHE_TYPE=redis`       |
| 5+ pods / DDoS protection | `redis-aside` ¹     | `USER_CACHE_TYPE=redis-aside` |

¹ `redis-aside` requires **Redis >= 7.0** (RESP3 client-side caching). Use `redis` for older Redis versions.

See the [User Cache configuration section](CONFIGURATION.md#user-cache) for all options.

---

## Load Testing

### Using Apache Bench (ab)

```bash
# Test health endpoint
ab -n 10000 -c 100 http://localhost:8080/health

# Test device code generation
ab -n 1000 -c 50 -p device-code.json -T application/json \
  http://localhost:8080/oauth/device/code

# device-code.json:
# {"client_id":"your-client-id"}
```

### Using wrk

```bash
# Install wrk
git clone https://github.com/wg/wrk.git
cd wrk && make

# Run benchmark
./wrk -t4 -c100 -d30s http://localhost:8080/health

# With script for POST requests
./wrk -t4 -c100 -d30s -s device-code.lua http://localhost:8080/oauth/device/code
```

**device-code.lua:**

```lua
wrk.method = "POST"
wrk.body   = '{"client_id":"your-client-id"}'
wrk.headers["Content-Type"] = "application/json"
```

### Using k6

```bash
# Install k6
brew install k6  # macOS
# or download from https://k6.io/

# Create test script
cat > load-test.js <<EOF
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  vus: 100,
  duration: '30s',
};

export default function () {
  let response = http.get('http://localhost:8080/health');
  check(response, {
    'status is 200': (r) => r.status === 200,
  });
  sleep(1);
}
EOF

# Run test
k6 run load-test.js
```

---

## Comparison with Other Solutions

| Feature          | AuthGate      | Auth0  | Keycloak     | Custom OAuth |
| ---------------- | ------------- | ------ | ------------ | ------------ |
| Device Flow      | ✅            | ✅     | ✅           | 🔧 DIY       |
| Self-Hosted      | ✅            | ❌     | ✅           | ✅           |
| Lightweight      | ✅ (< 20MB)   | N/A    | ❌ (> 500MB) | 🔧 Varies    |
| Setup Time       | 5 min         | 15 min | 1 hour       | Days         |
| Learning Curve   | Low           | Medium | High         | High         |
| Cost             | Free (OSS)    | $$$    | Free (OSS)   | Dev Time     |
| Production Ready | ✅ (w/ audit) | ✅     | ✅           | 🔧 Varies    |
| Multi-tenancy    | ❌ (DIY)      | ✅     | ✅           | 🔧 DIY       |
| Embedded Binary  | ✅            | N/A    | ❌           | 🔧 Varies    |
| Performance      | ~500 req/s    | ~5000  | ~1000        | Varies       |
| Memory Usage     | ~50MB         | N/A    | ~500MB       | Varies       |

### When to Choose AuthGate

✅ **Good fit:**

- Small to medium deployments
- Need full control over authentication
- Want simple, lightweight solution
- Require self-hosting
- Budget constraints
- Need device authorization flow

❌ **Not ideal:**

- > 10,000 active users (unless using PostgreSQL + scaling)
- Need enterprise SSO (SAML, LDAP)
- Require multi-tenancy out of the box
- Need advanced user management (roles, permissions)
- Require 24/7 vendor support

---

**Next Steps:**

- [Deployment Guide](DEPLOYMENT.md) - Production deployment options
- [Configuration Guide](CONFIGURATION.md) - Optimize configuration
- [Monitoring Guide](MONITORING.md) - Set up performance monitoring
