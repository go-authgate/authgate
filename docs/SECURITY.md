# Security Guide

This guide covers security best practices, threat model, and production hardening for AuthGate.

## Table of Contents

- [Production Deployment Checklist](#production-deployment-checklist)
- [Threat Model](#threat-model)
- [Secrets Management](#secrets-management)
- [TLS/HTTPS Configuration](#tlshttps-configuration)
- [Database Security](#database-security)
- [Session Security](#session-security)
- [Rate Limiting](#rate-limiting)
- [Audit and Compliance](#audit-and-compliance)
- [Incident Response](#incident-response)

---

## Production Deployment Checklist

Before deploying AuthGate to production, complete this security checklist:

### Secrets and Configuration

- [ ] Change `JWT_SECRET` to strong random value (32+ characters, use `openssl rand -hex 32`)
- [ ] Change `SESSION_SECRET` to strong random value (32+ characters)
- [ ] Set secure `DEFAULT_ADMIN_PASSWORD` (or immediately change auto-generated password)
- [ ] Never commit secrets to version control
- [ ] Use environment variables or secrets management system
- [ ] Rotate secrets regularly (JWT_SECRET: every 90 days, SESSION_SECRET: every 180 days)

### Network Security

- [ ] Use HTTPS exclusively (set `BASE_URL` to `https://...`)
- [ ] Obtain valid SSL/TLS certificates (Let's Encrypt or commercial CA)
- [ ] Configure firewall rules (only expose ports 80, 443)
- [ ] Use reverse proxy (Nginx, Caddy) for additional security layers
- [ ] Enable HTTP/2 for better performance
- [ ] Configure proper CORS policies if needed

### Token Configuration

- [ ] Set appropriate `DeviceCodeExpiration` (default: 30 minutes)
- [ ] Set appropriate `JWTExpiration` (default: 1 hour, max: 24 hours)
- [ ] Set appropriate `REFRESH_TOKEN_EXPIRATION` (default: 30 days)
- [ ] Consider enabling token rotation for high-security scenarios (`ENABLE_TOKEN_ROTATION=true`)
- [ ] Review token scopes and ensure least privilege

### Rate Limiting

- [ ] **Enable rate limiting** (enabled by default)
- [ ] Use Redis store for multi-pod deployments (`RATE_LIMIT_STORE=redis`)
- [ ] Adjust limits based on traffic patterns
- [ ] Monitor rate limit events in audit logs
- [ ] Set up alerts for excessive rate limiting

### Audit Logging

- [ ] **Enable audit logging** (enabled by default)
- [ ] Set appropriate retention period (`AUDIT_LOG_RETENTION`, default: 90 days)
- [ ] Monitor audit log storage growth
- [ ] Set up regular exports for compliance (CSV available)
- [ ] Review audit logs regularly for security incidents
- [ ] Set up alerts for critical audit events

### Database Security

- [ ] Use PostgreSQL for production (more secure than SQLite)
- [ ] Enable database encryption at rest
- [ ] Regularly backup database (automated daily backups)
- [ ] Restrict database access (localhost only or private network)
- [ ] Use strong database passwords
- [ ] Enable database SSL/TLS connections

### Application Security

- [ ] Run as non-root user (Docker: UID 1000, Systemd: dedicated user)
- [ ] Use Docker non-root user mode (already configured in Dockerfile)
- [ ] Configure timeouts (ReadTimeout, WriteTimeout, IdleTimeout)
- [ ] Set up automated cleanup for expired tokens and device codes
- [ ] Implement secure session management (7-day expiry, encrypted cookies)
- [ ] Enable CSRF protection (already enabled)

### Monitoring and Operations

- [ ] Monitor `/health` endpoint for service availability
- [ ] Set up log aggregation (Loki, Papertrail, CloudWatch)
- [ ] Configure alerts for critical errors
- [ ] Monitor failed login attempts
- [ ] Track unusual authentication patterns
- [ ] Set up automated backup verification

### User Education

- [ ] Educate users to use `/account/sessions` to review active devices
- [ ] Provide clear instructions for revoking suspicious sessions
- [ ] Document incident response procedures
- [ ] Train administrators on security best practices

---

## Threat Model

### What AuthGate Protects Against

✅ **Client Secret Exposure in Distributed Apps**

- Device Authorization Flow doesn't require embedding secrets in CLI tools
- Device codes are short-lived (30 minutes) and single-use

✅ **Phishing Attacks**

- User authorizes on trusted domain (your AuthGate instance)
- Device codes displayed in CLI, not entered by user
- Verification URI clearly shows your domain

✅ **Replay Attacks**

- Device codes are single-use (marked as used after authorization)
- JWTs have expiration times and signature verification
- CSRF tokens protect state-changing operations

✅ **Token Tampering**

- JWTs signed with HMAC-SHA256 (or external provider)
- Signature verification on every request
- Token claims cannot be modified without detection

✅ **Brute Force Attacks**

- Rate limiting enabled by default (configurable per endpoint)
- IP-based tracking prevents single attacker from overwhelming service
- Failed login attempts logged in audit trail

✅ **API Abuse and DoS Attempts**

- Per-endpoint rate limits protect critical paths
- Memory or Redis store for distributed rate limiting
- Graceful degradation when limits are exceeded

✅ **Session Hijacking**

- Encrypted session cookies (AES-256)
- HttpOnly and Secure flags on cookies
- Session fingerprinting support (configurable)
- 7-day session expiration (configurable)

### What You Must Secure

🔒 **Server Host Security**

- OS hardening and security updates
- Firewall configuration
- SSH key management
- Intrusion detection system (IDS)

🔒 **Database Encryption at Rest**

- Use encrypted volumes (LUKS, AWS EBS encryption)
- Secure database backups (encrypted storage)
- Restrict database file permissions (0600)

🔒 **TLS/HTTPS in Production**

- Valid SSL certificates (not self-signed)
- Strong cipher suites (TLSv1.2+)
- HSTS headers (Strict-Transport-Security)

🔒 **Secret Rotation Policies**

- Regular rotation of JWT_SECRET (every 90 days)
- Session secret rotation (every 180 days)
- Admin password changes (every 90 days)
- OAuth client secret rotation (as needed)

🔒 **Network Isolation**

- Place database on private network
- Restrict external access to application port only
- Use VPN for administrative access

---

## Secrets Management

### Generate Strong Secrets

```bash
# Generate 256-bit secrets
openssl rand -hex 32

# Or use /dev/urandom
head -c 32 /dev/urandom | base64
```

### Store Secrets Securely

**Option 1: Environment Variables (Docker, Systemd)**

```bash
# .env file (set permissions to 0600)
JWT_SECRET=abc123...
SESSION_SECRET=def456...

# Restrict permissions
chmod 600 .env
chown authgate:authgate .env
```

**Option 2: Secrets Management Systems**

**HashiCorp Vault:**

```bash
# Store secret
vault kv put secret/authgate JWT_SECRET=abc123...

# Retrieve in startup script
export JWT_SECRET=$(vault kv get -field=JWT_SECRET secret/authgate)
```

**AWS Secrets Manager:**

```bash
# Store secret
aws secretsmanager create-secret --name authgate-jwt-secret --secret-string "abc123..."

# Retrieve in application
aws secretsmanager get-secret-value --secret-id authgate-jwt-secret
```

**Kubernetes Secrets:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: authgate-secrets
type: Opaque
data:
  jwt-secret: YWJjMTIzLi4u # base64 encoded
  session-secret: ZGVmNDU2Li4u
```

### Secret Rotation

**Rotating JWT_SECRET:**

1. Generate new secret: `openssl rand -hex 32`
2. Schedule maintenance window (brief service interruption)
3. Update `JWT_SECRET` in configuration
4. Restart service
5. All existing tokens become invalid (users must re-authenticate)
6. Consider implementing dual-key verification during rotation

**Rotating SESSION_SECRET:**

1. Generate new secret
2. Update `SESSION_SECRET` in configuration
3. Restart service
4. All existing sessions become invalid (users must re-login)

---

## TLS/HTTPS Configuration

### Obtain SSL Certificate (Let's Encrypt)

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d auth.yourdomain.com

# Auto-renewal (configured automatically)
sudo certbot renew --dry-run
```

### Nginx SSL Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;

    # Modern SSL configuration (Mozilla SSL Configuration Generator)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (15768000 seconds = 6 months)
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains" always;

    # Additional security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # ... proxy configuration
}
```

### Test SSL Configuration

```bash
# Test with SSL Labs
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=auth.yourdomain.com

# Test locally
openssl s_client -connect auth.yourdomain.com:443 -tls1_2
```

---

## Database Security

### SQLite Security (Development/Small Deployments)

```bash
# Set proper file permissions
chmod 600 oauth.db
chown authgate:authgate oauth.db

# Enable WAL mode for better concurrency
sqlite3 oauth.db "PRAGMA journal_mode=WAL;"

# Regular backups
sqlite3 oauth.db ".backup /backup/oauth-$(date +%Y%m%d).db"
```

### PostgreSQL Security (Production)

**Connection Security:**

```bash
# Use SSL connections (postgresql.conf)
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'

# Require SSL for connections (pg_hba.conf)
hostssl all all 0.0.0.0/0 md5
```

**Database Hardening:**

```sql
-- Create dedicated user
CREATE USER authgate WITH PASSWORD 'strong-password';

-- Grant minimal permissions
GRANT CONNECT ON DATABASE authgate TO authgate;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authgate;

-- Revoke public schema access
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

**Encryption at Rest:**

```bash
# Enable transparent data encryption (TDE)
# Implementation varies by PostgreSQL version and platform
# Consult PostgreSQL documentation for your version
```

---

## Session Security

### Session Configuration

```bash
# Session settings in config/config.go
SessionSecret:  os.Getenv("SESSION_SECRET")
SessionMaxAge:  7 * 24 * 60 * 60  # 7 days
SessionSecure:  true              # HTTPS only
SessionHttpOnly: true             # Prevent XSS
SessionSameSite: "Lax"            # CSRF protection
```

### Session Fingerprinting (Optional)

Enable session fingerprinting to detect session hijacking:

```bash
# .env
ENABLE_SESSION_FINGERPRINTING=true
```

This creates a fingerprint from:

- User-Agent header
- IP address (optional)
- Accept-Language header

### Session Idle Timeout

Configure automatic session termination after inactivity:

```bash
# .env
SESSION_IDLE_TIMEOUT=1h  # Terminate after 1 hour of inactivity
```

---

## Rate Limiting

See [Configuration Guide - Rate Limiting](CONFIGURATION.md#rate-limiting) for complete documentation.

### Security Benefits

- **Prevents password brute force** (5 req/min on /login)
- **Mitigates device code enumeration** (10 req/min on /oauth/device/code)
- **Prevents user code guessing** (10 req/min on /device/verify)
- **Protects against DoS** (configurable limits per endpoint)
- **Per-IP tracking** (prevents single attacker from overwhelming service)

### Production Configuration

```bash
# .env
ENABLE_RATE_LIMIT=true
RATE_LIMIT_STORE=redis  # For multi-pod deployments
REDIS_ADDR=redis-service:6379
REDIS_PASSWORD=secure-password

# Adjust limits based on your traffic
LOGIN_RATE_LIMIT=5
DEVICE_CODE_RATE_LIMIT=10
TOKEN_RATE_LIMIT=20
DEVICE_VERIFY_RATE_LIMIT=10
```

---

## Audit and Compliance

### Enable Comprehensive Auditing

```bash
# .env
ENABLE_AUDIT_LOGGING=true
AUDIT_LOG_RETENTION=2160h  # 90 days (adjust for compliance)
```

### Compliance Requirements

**SOC 2:**

- Audit all authentication events
- Track all token operations
- Monitor failed login attempts
- Export audit logs regularly

**ISO 27001:**

- Retain audit logs for required period (90 days minimum)
- Implement automated cleanup
- Protect audit logs from tampering

**GDPR:**

- Log data access events
- Track consent (if applicable)
- Provide audit trail for data subject requests
- Implement data retention policies

### Regular Security Reviews

- **Weekly**: Review failed authentication attempts
- **Monthly**: Analyze rate limit events and suspicious patterns
- **Quarterly**: Export audit logs for compliance reporting
- **Annually**: Full security audit and penetration testing

---

## Incident Response

### Security Incident Playbook

**Step 1: Detection**

- Monitor for critical audit events
- Review failed authentication patterns
- Check rate limit exceeded alerts
- Analyze unusual traffic patterns

**Step 2: Containment**

```bash
# Immediately revoke all tokens for affected user
curl -X POST https://auth.yourdomain.com/account/sessions/revoke-all \
  -H "Cookie: session=..."

# Block attacker IP at firewall level
sudo iptables -A INPUT -s <attacker-ip> -j DROP

# Temporarily disable affected OAuth client
# (Update database or use admin interface)
```

**Step 3: Investigation**

```bash
# Export audit logs for analysis
curl "https://auth.yourdomain.com/admin/audit/export?since=24h" \
  -H "Cookie: admin-session=..." -o incident-logs.csv

# Review systemd logs
sudo journalctl -u authgate --since "24 hours ago" > authgate-incident.log

# Check database for anomalies
sqlite3 oauth.db "SELECT * FROM audit_logs WHERE severity='CRITICAL' AND event_time > datetime('now', '-24 hours');"
```

**Step 4: Remediation**

- Rotate affected secrets (JWT_SECRET, SESSION_SECRET)
- Force password reset for affected users
- Patch vulnerabilities if applicable
- Update firewall rules
- Review and update rate limits

**Step 5: Recovery**

- Restore from backup if data was compromised
- Re-enable affected services
- Communicate with affected users
- Document incident in incident report

**Step 6: Post-Incident Review**

- Analyze root cause
- Update security procedures
- Implement additional controls
- Schedule follow-up review

### Contact Information

Maintain an up-to-date incident response contact list:

- **Security Team**: security@yourdomain.com
- **On-Call Engineer**: [phone number]
- **Platform Provider**: [support contact]
- **Legal/Compliance**: [contact info]

---

## Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [RFC 8725 - JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

**Next Steps:**

- [Deployment Guide](DEPLOYMENT.md) - Production deployment
- [Monitoring Guide](MONITORING.md) - Set up monitoring and alerts
- [Troubleshooting](TROUBLESHOOTING.md) - Debug security issues
