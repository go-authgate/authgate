# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with AuthGate.

## Table of Contents

- [Common Issues](#common-issues)
- [Debug Mode](#debug-mode)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
- [Getting Help](#getting-help)

---

## Common Issues

### Issue: "Client not found" error

**Symptoms:**

```json
{
  "error": "invalid_client",
  "error_description": "Client not found"
}
```

**Cause:** The `CLIENT_ID` in your CLI application doesn't match any registered OAuth client in the database.

**Solution:**

1. Check server logs on first startup for the seeded client ID:

```bash
# View server logs
./bin/authgate server
# Look for: "Seeded OAuth client with ID: abc-123-def"

# Or check systemd logs
sudo journalctl -u authgate | grep "Seeded OAuth client"
```

2. Update your CLI `.env` file with the correct `CLIENT_ID`:

```bash
# device-cli/.env
CLIENT_ID=abc-123-def-456-789
```

3. Or query the database directly:

```bash
sqlite3 oauth.db "SELECT client_id, name FROM oauth_clients;"
```

---

### Issue: Database locked errors

**Symptoms:**

```
Error 1555: database is locked
SQLITE_BUSY: database is locked
```

**Cause:** SQLite doesn't handle high concurrency well. Multiple processes or threads trying to write simultaneously cause lock contention.

**Solutions:**

**Option 1: Enable WAL Mode (Write-Ahead Logging)**

```bash
# Enable WAL mode for better concurrency
sqlite3 oauth.db "PRAGMA journal_mode=WAL;"
```

**Option 2: Ensure Single Instance**

```bash
# Stop all instances
pkill authgate

# Remove lock files
rm oauth.db-shm oauth.db-wal

# Start single instance
./bin/authgate server
```

**Option 3: Use PostgreSQL (Recommended for Production)**

```bash
# .env
DATABASE_DRIVER=postgres
DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=require"
```

PostgreSQL handles concurrent connections much better than SQLite.

---

### Issue: "authorization_pending" never resolves

**Symptoms:**

CLI keeps polling but never receives a token:

```
Waiting for authorization... (authorization_pending)
Waiting for authorization... (authorization_pending)
...
```

**Cause:** User didn't complete authorization in browser, or device code expired.

**Solution:**

1. **Check device code expiration:**

```bash
# Default: 30 minutes
# Check if device code is still valid
sqlite3 oauth.db "SELECT device_code, expires_at FROM device_codes WHERE device_code='xxx';"
```

2. **Verify user completed authorization:**

- User must visit the verification URL
- User must login (if not already authenticated)
- User must enter the exact user code (case-insensitive)
- User must click "Authorize Device"

3. **Check server logs for errors:**

```bash
# Systemd
sudo journalctl -u authgate -f

# Docker
docker logs -f authgate

# Look for errors during /device/verify
```

4. **Common user mistakes:**

- Entered wrong user code
- Typo in user code
- Used expired device code (> 30 minutes old)
- Network issues preventing form submission

5. **Debug verification process:**

```bash
# Check device code status
sqlite3 oauth.db "SELECT * FROM device_codes WHERE user_code='XXXX-XXXX';"

# Look for is_used=1 (authorized) or user_id being set
```

---

### Issue: "Username conflict with existing user" error

**Symptoms:**

User sees error when logging in via external HTTP API:

```
Username conflict with existing user. Please contact administrator.
```

**Cause:** The username returned by the external authentication API matches an existing user in the local database with a different `external_id` or `auth_source`.

**Resolution Options:**

**Option 1: Rename Existing Local User**

If the conflicting user is a different person:

```sql
-- Update the existing user's username
sqlite3 oauth.db "UPDATE users SET username='olduser-renamed' WHERE username='conflicting-username';"
```

**Option 2: Configure External API to Use Different Username**

Update your external authentication service to return unique usernames (e.g., append domain):

```json
{
  "success": true,
  "user_id": "external-123",
  "username": "john@company.com", // Instead of just "john"
  "email": "john@company.com"
}
```

**Option 3: Manual Account Merge**

If it's the same person, manually update the local user:

```sql
-- Ensure the local user has correct auth_source and external_id
UPDATE users
SET auth_source='http_api', external_id='external-user-id'
WHERE username='conflicting-username';
```

**Prevention:**

Use namespaced usernames in external API (e.g., email addresses instead of short usernames).

---

### Issue: JWT signature verification fails

**Symptoms:**

```json
{
  "error": "invalid_token",
  "error_description": "Token signature verification failed"
}
```

**Cause:** `JWT_SECRET` changed between token issuance and verification, or token was tampered with.

**Solution:**

1. **Verify JWT_SECRET consistency:**

```bash
# Check current JWT_SECRET
grep JWT_SECRET .env

# Ensure it hasn't changed since tokens were issued
```

2. **Don't change JWT_SECRET with active tokens:**

If you must change it:

- Schedule maintenance window
- Notify users that they'll need to re-authenticate
- Change `JWT_SECRET`
- Restart service
- All existing tokens become invalid

3. **Check for token tampering:**

```bash
# Decode JWT to inspect claims (without verification)
echo "eyJhbGc..." | base64 -d

# Look for unexpected modifications
```

4. **Verify token provider configuration:**

```bash
# If using TOKEN_PROVIDER_MODE=http_api
# Ensure external service is reachable and using correct signing key
curl -X POST https://token-api.example.com/api/validate \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGc..."}'
```

---

### Issue: Session not persisting

**Symptoms:**

- User logs in successfully but gets redirected to login page
- Session cookie not being set
- User appears logged out after page refresh

**Cause:** Session configuration issues or cookie problems.

**Solution:**

1. **Verify SESSION_SECRET is set:**

```bash
# Check .env
grep SESSION_SECRET .env

# Must be non-empty and consistent
```

2. **Check BASE_URL matches access domain:**

```bash
# .env
BASE_URL=https://auth.yourdomain.com  # Must match the domain you're accessing

# If accessing via IP, set:
BASE_URL=http://192.168.1.100:8080
```

3. **Verify cookies are enabled in browser:**

```javascript
// In browser console
document.cookie;
// Should show session cookie
```

4. **Check Secure flag in production:**

```bash
# If using HTTPS, ensure Secure flag is set
# In config/config.go:
SessionSecure: true  // Only for HTTPS
```

5. **Review session cookie settings:**

```go
// middleware/auth.go
store := cookie.NewStore([]byte(cfg.SessionSecret))
store.Options(sessions.Options{
    Path:     "/",
    MaxAge:   cfg.SessionMaxAge,
    HttpOnly: true,
    Secure:   cfg.SessionSecure,  // Must be false for HTTP
    SameSite: http.SameSiteLaxMode,
})
```

6. **Check for domain mismatch:**

- Cookie domain must match access domain
- Subdomains may have cookie issues
- localhost vs 127.0.0.1 can cause problems

---

### Issue: Rate limit triggered unexpectedly

**Symptoms:**

```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please try again later."
}
```

**Cause:** Request rate exceeded configured limits.

**Solution:**

1. **Check current rate limits:**

```bash
# View configuration
grep RATE_LIMIT .env

# Default limits:
# LOGIN_RATE_LIMIT=5          # 5 req/min
# DEVICE_CODE_RATE_LIMIT=10   # 10 req/min
# TOKEN_RATE_LIMIT=20         # 20 req/min
```

2. **Adjust limits for your use case:**

```bash
# For higher traffic, increase limits
TOKEN_RATE_LIMIT=50         # 50 req/min
DEVICE_CODE_RATE_LIMIT=30   # 30 req/min
```

3. **Check if behind proxy:**

If behind a reverse proxy, ensure real IP is forwarded:

```nginx
# Nginx configuration
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

4. **Temporarily disable for debugging:**

```bash
# .env
ENABLE_RATE_LIMIT=false

# Don't use this in production!
```

5. **Review audit logs for patterns:**

```bash
# Check for suspicious activity
curl "http://localhost:8080/admin/audit/api?event_type=RATE_LIMIT_EXCEEDED" \
  -H "Cookie: session=..."
```

---

### Issue: External HTTP API authentication fails

**Symptoms:**

```
Authentication failed: connection refused
timeout waiting for authentication response
```

**Cause:** External authentication API is unreachable or misconfigured.

**Solution:**

1. **Verify HTTP_API_URL is correct:**

```bash
# Test connectivity
curl -X POST https://auth.example.com/api/verify \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
```

2. **Check timeout settings:**

```bash
# .env
HTTP_API_TIMEOUT=30s  # Increase if API is slow
```

3. **Verify service-to-service authentication:**

```bash
# If using HMAC mode
HTTP_API_AUTH_MODE=hmac
HTTP_API_AUTH_SECRET=your-shared-secret

# Test with proper headers
curl -X POST https://auth.example.com/api/verify \
  -H "X-Signature: <hmac-signature>" \
  -H "X-Timestamp: $(date +%s)" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
```

4. **Check network connectivity:**

```bash
# Test DNS resolution
nslookup auth.example.com

# Test TCP connection
telnet auth.example.com 443

# Check firewall rules
sudo iptables -L | grep auth.example.com
```

5. **Review retry configuration:**

```bash
# Enable aggressive retries for flaky networks
HTTP_API_MAX_RETRIES=5
HTTP_API_RETRY_DELAY=2s
HTTP_API_MAX_RETRY_DELAY=30s
```

---

## Debug Mode

### Enable Debug Logging

**Gin Debug Mode:**

```bash
# Enable detailed HTTP request logging
GIN_MODE=debug ./bin/authgate server
```

Output includes:

```
[GIN-debug] GET    /health                   --> main.healthCheck (3 handlers)
[GIN-debug] POST   /oauth/device/code        --> handlers.(*DeviceHandler).RequestDeviceCode
[GIN-debug] Listening and serving HTTP on :8080
[GIN] 2026/02/08 - 10:00:00 | 200 |    1.234ms |  192.168.1.1 | GET "/health"
```

**GORM Debug Mode:**

Enable in `store/sqlite.go`:

```go
// Add to database queries
db.Debug().Where("username = ?", username).First(&user)
```

Output shows SQL queries:

```sql
[2026-02-08 10:00:00] SELECT * FROM users WHERE username = 'admin' LIMIT 1
```

### Increase Log Verbosity

```bash
# Systemd: view all logs including debug messages
sudo journalctl -u authgate -f --all

# Docker: include timestamps
docker logs -f --timestamps authgate
```

### Trace HTTP Requests

```bash
# Use httpie for detailed request/response
http POST http://localhost:8080/oauth/device/code \
  client_id=xxx \
  --verbose

# Or curl with verbose output
curl -v -X POST http://localhost:8080/oauth/device/code \
  -d "client_id=xxx"
```

---

## Frequently Asked Questions (FAQ)

### Q: Why not use OAuth password grant?

**A:** Password grant requires users to enter credentials directly into your app, which trains users to trust third parties with passwords (security anti-pattern). Device Authorization Grant keeps credentials on the trusted authorization server.

### Q: Can I use this in production?

**A:** Yes, but ensure you follow the [Security Checklist](SECURITY.md#production-deployment-checklist) and harden the deployment. This is a reference implementation - audit it for your specific needs.

### Q: How do I add user registration?

**A:** Implement registration handlers in `handlers/auth.go` and update the database schema in `models/user.go`. Consider adding email verification and CAPTCHA for public registrations.

### Q: Can I use this with multiple clients?

**A:** Yes! Add additional clients to the `oauth_clients` table with unique `client_id` values. Each client can have different redirect URIs and scopes.

### Q: What about token refresh?

**A:** AuthGate fully supports refresh tokens (RFC 6749) with two modes:

- **Fixed Mode (Default)**: Refresh tokens are reusable, perfect for multi-device scenarios
- **Rotation Mode**: High-security mode where each refresh returns new tokens

Configure via:

```bash
REFRESH_TOKEN_EXPIRATION=720h        # 30 days
ENABLE_REFRESH_TOKENS=true
ENABLE_TOKEN_ROTATION=false          # Set true for rotation mode
```

### Q: How do users revoke device access?

**A:** Users have multiple options:

- **Web UI:** Visit `/account/sessions` to view and revoke individual devices
- **CLI/API:** Call `POST /oauth/revoke` with the token parameter
- **Revoke All:** Use "Revoke All" button to sign out all devices at once

### Q: How long do device codes last?

**A:** Device codes expire after 30 minutes by default. This is configurable via `Config.DeviceCodeExpiration` in `config/config.go`.

### Q: Can I use a different database?

**A:** Yes! AuthGate supports both SQLite and PostgreSQL:

**SQLite (default):**

```bash
DATABASE_DRIVER=sqlite
DATABASE_DSN=oauth.db
```

**PostgreSQL:**

```bash
DATABASE_DRIVER=postgres
DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=disable"
```

The database driver uses a factory pattern and can be extended to support MySQL. See `store/driver.go`.

### Q: How do I change the polling interval?

**A:** The polling interval is 5 seconds by default (RFC 8628 compliant). Modify `Config.PollingInterval` in `config/config.go`:

```go
PollingInterval: 5 * time.Second,  // Change to your preferred interval
```

### Q: Are user codes case-sensitive?

**A:** No, user codes are normalized to uppercase and dashes are removed before lookup:

- `ABCD-1234` = `abcd1234` = `ABCD1234`

This improves user experience when manually entering codes.

### Q: How do I migrate from SQLite to PostgreSQL?

**A:** Use the `pgloader` tool:

```bash
# Install pgloader
sudo apt-get install pgloader

# Create PostgreSQL database
createdb authgate

# Migrate data
pgloader oauth.db postgresql://localhost/authgate

# Update .env
DATABASE_DRIVER=postgres
DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=require"

# Restart service
sudo systemctl restart authgate
```

### Q: Can I customize the web UI?

**A:** Yes, but it requires rebuilding the application:

1. Modify templates in `templates/*.templ`
2. Regenerate template code: `go generate ./templates`
3. Rebuild: `make build`

Templates use [templ](https://templ.guide/) for type-safe HTML templating.

### Q: How do I backup the database?

**SQLite:**

```bash
# Online backup
sqlite3 oauth.db ".backup /backup/oauth-$(date +%Y%m%d).db"

# Or simple copy (stop service first)
sudo systemctl stop authgate
cp oauth.db /backup/oauth-$(date +%Y%m%d).db
sudo systemctl start authgate
```

**PostgreSQL:**

```bash
# Dump database
pg_dump authgate > backup-$(date +%Y%m%d).sql

# Restore
psql authgate < backup-20260208.sql
```

### Q: What's the difference between "disabled" and "revoked" tokens?

**A:**

- **Disabled**: Token is temporarily blocked but can be re-enabled later
- **Revoked**: Token is permanently blocked and cannot be used again

Use "disable" for temporary account suspensions, "revoke" for security incidents.

---

## Getting Help

### Check Existing Issues

Search for similar issues in the GitHub repository:

```
https://github.com/go-authgate/authgate/issues
```

### Report a Bug

Open an issue with:

1. **AuthGate version**: `./bin/authgate -v`
2. **Operating system**: `uname -a`
3. **Database**: SQLite or PostgreSQL version
4. **Steps to reproduce**
5. **Expected vs actual behavior**
6. **Relevant logs** (sanitize sensitive data)

### Security Issues

For security vulnerabilities, please email security@yourdomain.com instead of opening a public issue.

### Community Support

- GitHub Discussions: Ask questions and share tips
- Stack Overflow: Tag questions with `authgate` and `oauth2`

---

**Next Steps:**

- [Configuration Guide](CONFIGURATION.md) - Advanced configuration
- [Security Guide](SECURITY.md) - Security best practices
- [Monitoring Guide](MONITORING.md) - Set up monitoring and alerts
