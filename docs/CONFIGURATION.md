# Configuration Guide

This guide covers all configuration options for AuthGate, including environment variables, secrets management, and advanced features.

## Table of Contents

- [Environment Variables](#environment-variables)
- [TLS / HTTPS](#tls--https)
- [Bootstrap and Shutdown Timeouts](#bootstrap-and-shutdown-timeouts)
- [Generate Strong Secrets](#generate-strong-secrets)
- [Token Lifetime Profiles](#token-lifetime-profiles)
- [Caller-Supplied Extra Claims](#caller-supplied-extra-claims)
- [Default Test Data](#default-test-data)
- [OAuth Third-Party Login](#oauth-third-party-login)
- [Service-to-Service Authentication](#service-to-service-authentication)
- [HTTP Retry with Exponential Backoff](#http-retry-with-exponential-backoff)
- [User Cache](#user-cache)
- [Client Cache](#client-cache)
- [Token Cache](#token-cache)
- [Rate Limiting](#rate-limiting)
- [CORS (Cross-Origin Resource Sharing)](#cors-cross-origin-resource-sharing)

---

## Environment Variables

Create a `.env` file in the project root:

```bash
# Server Configuration
SERVER_ADDR=:8080                # Listen address (e.g., :8080, 0.0.0.0:8080)
BASE_URL=http://localhost:8080   # Public URL for verification_uri

# TLS / HTTPS (optional) — set both to serve HTTPS on SERVER_ADDR
# TLS_CERT_FILE=/etc/authgate/tls/fullchain.pem
# TLS_KEY_FILE=/etc/authgate/tls/privkey.pem

# Security - CHANGE THESE IN PRODUCTION!
JWT_SECRET=your-256-bit-secret-change-in-production       # HMAC-SHA256 signing key
SESSION_SECRET=session-secret-change-in-production        # Cookie encryption key

# Database
DATABASE_DRIVER=sqlite           # Database driver: "sqlite" or "postgres"
DATABASE_DSN=oauth.db            # Connection string (file path for SQLite, DSN for PostgreSQL)

# PostgreSQL Example:
# DATABASE_DRIVER=postgres
# DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=disable"

# Database Log Level
# DB_LOG_LEVEL=warn              # GORM log level: "silent", "error", "warn" (default), "info"

# Default Admin User
# Set a custom password for the default admin user created on first startup
# If not set, a random 16-character password will be generated and written to authgate-credentials.txt
# DEFAULT_ADMIN_PASSWORD=your-secure-admin-password

# Authentication Mode
# Options: local, http_api
# Default: local
AUTH_MODE=local

# HTTP API Authentication (when AUTH_MODE=http_api)
HTTP_API_URL=https://auth.example.com/api/verify
HTTP_API_TIMEOUT=10s
HTTP_API_INSECURE_SKIP_VERIFY=false

# HTTP API Retry Configuration
# Automatic retry with exponential backoff for failed requests
HTTP_API_MAX_RETRIES=3           # Maximum retry attempts (default: 3, set 0 to disable)
HTTP_API_RETRY_DELAY=1s          # Initial retry delay (default: 1s)
HTTP_API_MAX_RETRY_DELAY=10s     # Maximum retry delay (default: 10s)

# JWT Token Expiration
JWT_EXPIRATION=10h                   # Access token lifetime (default: 10h)
JWT_EXPIRATION_JITTER=30m            # Max random jitter on access token expiry (default: 30m)
                                     # Must be less than JWT_EXPIRATION. Prevents refresh thundering herd.
                                     # Example: JWT_EXPIRATION=8h + JWT_EXPIRATION_JITTER=30m → lifetime [8h, 8h30m)

# JWT Audience Claim
# Comma-separated values written to the "aud" claim on issued access and refresh tokens.
# Single value emits "aud" as a string; multiple values as an array; empty omits the
# claim entirely (RFC 7519 §4.1.3). ID tokens are not affected — their "aud" stays
# the client_id per OIDC Core 1.0.
# JWT_AUDIENCE=                      # Default: unset (no aud claim)
# JWT_AUDIENCE=oa                    # → "aud": "oa"
# JWT_AUDIENCE=oa,swrd,hwrd          # → "aud": ["oa", "swrd", "hwrd"]

# JWT Domain Claim — server-attested
# Server-set "domain" claim emitted on every issued access, refresh, and
# client-credentials JWT. Identifies which AuthGate deployment minted a token.
# Identifier shape: 1–64 chars of [A-Za-z0-9_.-], starting and ending with an
# alphanumeric (same shape as the per-client `project` claim). Emitted verbatim
# (case preserved). Empty → claim omitted entirely. Server-set: it cannot be
# spoofed via /oauth/token's extra_claims and is re-resolved on every refresh,
# so flipping the env var propagates on the next refresh request.
# JWT_DOMAIN=                        # Default: unset (no domain claim)
# JWT_DOMAIN=oa                      # → "domain": "oa"

# Refresh Token Configuration
REFRESH_TOKEN_EXPIRATION=720h        # Refresh token lifetime (default: 30 days)
ENABLE_REFRESH_TOKENS=true          # Feature flag to enable/disable refresh tokens
ENABLE_TOKEN_ROTATION=false         # Enable rotation mode (default: fixed mode)

# Client Credentials Flow (RFC 6749 §4.4)
# CLIENT_CREDENTIALS_TOKEN_EXPIRATION=1h  # Access token lifetime for client_credentials grant (default: 1h)
#                                           # Keep short — no refresh token means no rotation mechanism
#                                           # Governed independently from per-client TokenProfile (see below)

# Per-Client Token Lifetime Profiles
# Each OAuth client selects one of three presets: "short", "standard" (default), or "long".
# "standard" defaults to JWT_EXPIRATION / REFRESH_TOKEN_EXPIRATION above; overrides below
# let you tailor the short/long presets without touching the base defaults.
# TOKEN_PROFILE_SHORT_ACCESS_TTL=15m       # Short profile access token lifetime (default: 15m)
# TOKEN_PROFILE_SHORT_REFRESH_TTL=24h      # Short profile refresh token lifetime (default: 24h)
# TOKEN_PROFILE_STANDARD_ACCESS_TTL=10h    # Standard profile access TTL (default: JWT_EXPIRATION)
# TOKEN_PROFILE_STANDARD_REFRESH_TTL=720h  # Standard profile refresh TTL (default: REFRESH_TOKEN_EXPIRATION)
# TOKEN_PROFILE_LONG_ACCESS_TTL=24h        # Long profile access TTL (default: 24h)
# TOKEN_PROFILE_LONG_REFRESH_TTL=2160h     # Long profile refresh TTL (default: 90 days)
#
# Hard caps — enforced at startup. No profile may exceed these values.
# JWT_EXPIRATION_MAX=24h                   # Upper bound for any access-token profile (default: 24h)
# REFRESH_TOKEN_EXPIRATION_MAX=2160h       # Upper bound for any refresh-token profile (default: 90d)

# OAuth Configuration (optional - for third-party login)
# GitHub OAuth
GITHUB_OAUTH_ENABLED=false
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URL=http://localhost:8080/auth/callback/github
GITHUB_SCOPES=user:email

# Gitea OAuth
GITEA_OAUTH_ENABLED=false
GITEA_URL=https://gitea.example.com
GITEA_CLIENT_ID=your_gitea_client_id
GITEA_CLIENT_SECRET=your_gitea_client_secret
GITEA_REDIRECT_URL=http://localhost:8080/auth/callback/gitea
GITEA_SCOPES=read:user

# Microsoft Entra ID (Azure AD) OAuth
MICROSOFT_OAUTH_ENABLED=false
MICROSOFT_TENANT_ID=common
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_REDIRECT_URL=http://localhost:8080/auth/callback/microsoft
MICROSOFT_SCOPES=openid,profile,email,User.Read

# OAuth Settings
OAUTH_AUTO_REGISTER=true         # Allow OAuth to auto-create accounts (default: true)
OAUTH_TIMEOUT=15s                # HTTP client timeout for OAuth requests (default: 15s)
OAUTH_INSECURE_SKIP_VERIFY=false # Skip TLS verification for OAuth (dev/testing only, default: false)

# Authorization Code Flow (RFC 6749 + RFC 7636)
AUTH_CODE_EXPIRATION=10m            # Authorization code lifetime (default: 10 min)
PKCE_REQUIRED=false                 # Require PKCE for all clients, including confidential (default: false)
CONSENT_REMEMBER=true               # Skip consent page if user already approved same scopes (default: true)

# Dynamic Client Registration (RFC 7591)
ENABLE_DYNAMIC_CLIENT_REGISTRATION=false  # Enable POST /oauth/register (default: false)
DYNAMIC_CLIENT_REGISTRATION_TOKEN=        # Optional Bearer token for protected registration
DYNAMIC_CLIENT_REGISTRATION_RATE_LIMIT=5  # Rate limit (default: 5 req/min)

# User Cache
# Caches GetUserByID results — called on every protected request (RequireAuth + RequireAdmin)
# USER_CACHE_TYPE=memory              # Options: memory, redis, redis-aside (default: memory)
# USER_CACHE_TTL=5m                   # How long to cache a user object (default: 5m)
# USER_CACHE_CLIENT_TTL=30s           # Client-side TTL for redis-aside mode only (default: 30s)
# USER_CACHE_SIZE_PER_CONN=32         # Client-side cache size per connection in MB for redis-aside (default: 32MB)

# Audit Logging
# Comprehensive audit logging for security and compliance
ENABLE_AUDIT_LOGGING=true               # Enable audit logging (default: true)
AUDIT_LOG_RETENTION=2160h               # Retention period: 90 days (default: 90 days = 2160h)
AUDIT_LOG_BUFFER_SIZE=1000              # Async buffer size (default: 1000)
AUDIT_LOG_CLEANUP_INTERVAL=24h          # Cleanup frequency (default: 24h)

# Caller-Supplied Extra JWT Claims (extra_claims parameter on /oauth/token)
# Enabled by default. Reserved JWT/OIDC keys are always rejected. Custom
# claims are NOT persisted, so callers must re-supply extra_claims on every
# refresh to retain them. See "Caller-Supplied Extra Claims" section below.
EXTRA_CLAIMS_ENABLED=true               # Master switch (default: true)
EXTRA_CLAIMS_MAX_RAW_SIZE=4096          # Max raw JSON payload bytes (0 disables)
EXTRA_CLAIMS_MAX_KEYS=16                # Max top-level keys (0 disables)
EXTRA_CLAIMS_MAX_VAL_SIZE=512           # Max bytes per value (0 disables)
```

---

## TLS / HTTPS

AuthGate can serve HTTPS directly by setting two environment variables. When both are configured, the server listens on `SERVER_ADDR` using TLS. When both are empty (the default), it serves plain HTTP. Setting only one of the two is rejected at startup by `Config.Validate()` — this prevents silently falling back to HTTP when the operator meant to enable TLS.

```bash
TLS_CERT_FILE=/etc/authgate/tls/fullchain.pem   # PEM-encoded certificate (full chain)
TLS_KEY_FILE=/etc/authgate/tls/privkey.pem      # PEM-encoded private key
```

Notes:

- **Both variables must be set together.** Setting only one causes `Config.Validate()` to fail at startup (prevents accidental HTTP fallback when TLS was intended). Leave both empty for plain HTTP.
- **Use a full chain certificate** (leaf + intermediates). Clients often reject leaf-only certificates from non-root CAs.
- **Update `BASE_URL`** to `https://...` so OAuth redirect URIs, `verification_uri`, and JWKS links use the correct scheme.
- **Cipher suites / TLS versions** use Go's `crypto/tls` defaults — modern, secure, no tuning needed for typical deployments.
- **No hot reload.** Renewed certificates require restarting AuthGate. For zero-downtime certificate rotation (ACME/Let's Encrypt), terminate TLS at a reverse proxy (nginx, Caddy, Cloudflare) instead.

Quick local test with a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -days 1 -subj "/CN=localhost"
TLS_CERT_FILE=cert.pem TLS_KEY_FILE=key.pem BASE_URL=https://localhost:8080 \
  ./bin/authgate server
curl -k https://localhost:8080/health
```

---

## Bootstrap and Shutdown Timeouts

AuthGate supports configurable timeout durations for all lifecycle operations, enabling production tuning and graceful degradation.

### Overview

Initialization operations share a unified context flow from the graceful shutdown manager, while shutdown operations run with independent, timeout-bound contexts:

- **Initialization timeouts**: Control how long to wait for database, Redis, and cache connections during startup and are cancelled if the manager context is stopped (for example, with Ctrl+C)
- **Shutdown timeouts**: Control how long to wait for graceful cleanup of resources; each shutdown job runs with a fresh context derived from `context.Background()` and is bounded only by its configured timeout
- **Cancellation support**: Pressing Ctrl+C during startup cancels in-flight initialization work via the manager context; once shutdown has begun, shutdown work continues until its timeout expires, even if Ctrl+C is pressed again

### Configuration

All timeout values use Go duration format (e.g., `30s`, `1m`, `5m30s`):

```bash
# Database Initialization and Shutdown
DB_INIT_TIMEOUT=30s          # Database connection and migration timeout (default: 30s)
DB_CLOSE_TIMEOUT=5s          # Database connection close timeout (default: 5s)

# Redis Connection and Shutdown
REDIS_CONN_TIMEOUT=5s        # Redis connection health check timeout (default: 5s)
REDIS_CLOSE_TIMEOUT=5s       # Redis connection close timeout (default: 5s)

# Cache Initialization and Shutdown
CACHE_INIT_TIMEOUT=5s        # Cache initialization timeout (default: 5s)
CACHE_CLOSE_TIMEOUT=5s       # Cache close timeout (default: 5s)

# Server Graceful Shutdown
SERVER_SHUTDOWN_TIMEOUT=5s   # HTTP server graceful shutdown timeout (default: 5s)
AUDIT_SHUTDOWN_TIMEOUT=10s   # Audit service shutdown timeout (default: 10s)
```

### Use Cases

**Slow Network Connections**

```bash
# Increase timeouts for remote database/Redis
DB_INIT_TIMEOUT=60s
REDIS_CONN_TIMEOUT=15s
```

**Large Audit Buffer**

```bash
# Allow more time to flush audit logs on shutdown
AUDIT_SHUTDOWN_TIMEOUT=30s
```

**Fast Deployment Rollouts**

```bash
# Reduce shutdown timeouts for faster pod termination
SERVER_SHUTDOWN_TIMEOUT=3s
DB_CLOSE_TIMEOUT=2s
```

### Best Practices

1. **Keep close timeouts short** (5s or less) to prevent hanging on shutdown
2. **Increase init timeouts** for slow networks or large databases
3. **Match cache timeout** to your connection reliability
4. **Test timeout values** in staging before production
5. **Monitor timeout errors** in logs to tune values

### Behavior

- **Initialization**: If a timeout is exceeded, the application exits with an error
- **Shutdown**: Shutdown waits up to the configured timeout for close operations; if the timeout elapses, shutdown continues and reports a timeout error
- **Cancellation**: Pressing Ctrl+C triggers graceful shutdown and cancels operations that honor the manager context, but does not forcibly abort in-progress shutdown jobs
- **Errors**: Timeout errors include context (e.g., "database close timeout: context deadline exceeded")

---

## Generate Strong Secrets

```bash
# Generate JWT_SECRET (64 characters recommended)
openssl rand -hex 32

# Generate SESSION_SECRET (64 characters recommended)
openssl rand -hex 32

# Or use this one-liner to update .env
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env
echo "SESSION_SECRET=$(openssl rand -hex 32)" >> .env
```

---

## JWT Signing Algorithm

AuthGate supports three JWT signing algorithms:

| Algorithm | Type       | Key                          | Use Case                                |
| --------- | ---------- | ---------------------------- | --------------------------------------- |
| `HS256`   | Symmetric  | `JWT_SECRET` (shared secret) | Default, simple deployments             |
| `RS256`   | Asymmetric | RSA private key (2048+ bits) | Resource servers verify with public key |
| `ES256`   | Asymmetric | ECDSA P-256 private key      | Compact tokens, modern deployments      |

### Configuration

For RS256/ES256 you must supply the private key via **at least one** of two environment variables:

| Variable               | Use when                                                                           |
| ---------------------- | ---------------------------------------------------------------------------------- |
| `JWT_PRIVATE_KEY_PATH` | Key is available as a file on disk (bare-metal, Docker volume)                     |
| `JWT_PRIVATE_KEY_PEM`  | Key is injected as a string (Kubernetes Secret, GitHub Actions, Fly.io, Cloud Run) |

When both are set, `JWT_PRIVATE_KEY_PEM` wins and AuthGate logs a warning on startup.

```bash
# HS256 (default — no additional config needed)
JWT_SIGNING_ALGORITHM=HS256

# RS256 — load key from disk
JWT_SIGNING_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH=/path/to/rsa-private.pem
JWT_KEY_ID=                   # Optional: auto-generated from key fingerprint

# ES256 — load key from inline PEM (env var holds the full PEM content incl. newlines)
JWT_SIGNING_ALGORITHM=ES256
JWT_PRIVATE_KEY_PEM="-----BEGIN EC PRIVATE KEY-----
MHcCAQEEI...<base64 body>...
-----END EC PRIVATE KEY-----
"
JWT_KEY_ID=                   # Optional: auto-generated from key fingerprint
```

### Generate Keys

```bash
# RSA 2048-bit key for RS256
openssl genrsa -out rsa-private.pem 2048

# ECDSA P-256 key for ES256
openssl ecparam -genkey -name prime256v1 -noout -out ec-private.pem
```

### Loading Keys in Containerized Deployments

`JWT_PRIVATE_KEY_PEM` lets you pass the full PEM string through environment variables,
which is the native secret-delivery mechanism on most container platforms. Both
GitHub Actions Secrets and Kubernetes Secrets preserve newlines, so no base64 encoding
is required.

**GitHub Actions**

Store the PEM in a repository secret (e.g. `JWT_SIGNING_KEY`) — GitHub's secret editor
preserves multi-line input as-is. Then inject it at runtime:

```yaml
- name: Run AuthGate
  env:
    JWT_SIGNING_ALGORITHM: RS256
    JWT_PRIVATE_KEY_PEM: ${{ secrets.JWT_SIGNING_KEY }}
  run: ./bin/authgate server
```

**Kubernetes**

Store the PEM in a `Secret` and expose it via `env.valueFrom.secretKeyRef`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: authgate-jwt
type: Opaque
stringData:
  private-key.pem: |
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEI...
    -----END EC PRIVATE KEY-----
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authgate
spec:
  template:
    spec:
      containers:
        - name: authgate
          image: authgate:latest
          env:
            - name: JWT_SIGNING_ALGORITHM
              value: ES256
            - name: JWT_PRIVATE_KEY_PEM
              valueFrom:
                secretKeyRef:
                  name: authgate-jwt
                  key: private-key.pem
```

### JWKS Endpoint

When using RS256 or ES256, AuthGate exposes the public key at:

```
GET /.well-known/jwks.json
```

Resource servers can fetch this endpoint to verify JWT signatures without sharing secrets. The OIDC Discovery endpoint (`/.well-known/openid-configuration`) includes the `jwks_uri` field automatically when asymmetric keys are available. For a complete guide on verifying tokens at resource servers, see the [JWT Verification Guide](JWT_VERIFICATION.md).

The JWKS response includes a `Cache-Control: public, max-age=3600` header (1 hour). Resource servers should respect this cache directive; after key rotation, allow up to 1 hour for cached JWKS entries to expire.

For HS256, the JWKS endpoint returns an empty key set (`{"keys":[]}`) since symmetric secrets are never exposed.

### Supported Key Formats

AuthGate supports the following PEM-encoded private key formats:

| Format | PEM Header              | Algorithms  |
| ------ | ----------------------- | ----------- |
| PKCS#1 | `BEGIN RSA PRIVATE KEY` | RS256       |
| PKCS#8 | `BEGIN PRIVATE KEY`     | RS256/ES256 |
| SEC1   | `BEGIN EC PRIVATE KEY`  | ES256       |

PEM files with multiple blocks (e.g., `EC PARAMETERS` followed by `EC PRIVATE KEY`) are scanned automatically — the loader iterates through all blocks until it finds a supported key.

### Validation Rules

AuthGate validates signing keys at startup and rejects invalid configurations:

| Rule                          | Detail                                                          |
| ----------------------------- | --------------------------------------------------------------- |
| RS256 minimum key size        | 2048 bits (smaller RSA keys are rejected)                       |
| ES256 curve                   | P-256 only (P-384, P-521, and other curves are not supported)   |
| Key type must match algorithm | RSA key for RS256, ECDSA key for ES256                          |
| Key pair match                | Public key must correspond to the private key                   |
| Unknown algorithm             | Algorithms other than HS256/RS256/ES256 are rejected at startup |

### Key Rotation

Use `JWT_KEY_ID` to set an explicit `kid` (Key ID) header in JWTs. This enables key rotation:

1. Generate a new key pair
2. Update `JWT_PRIVATE_KEY_PATH` and `JWT_KEY_ID` to point to the new key
3. Restart the server — it will begin signing new tokens with the new key
4. Resource servers match the `kid` header to select the correct verification key from JWKS

> **Note**: The JWKS endpoint serves a single active public key at a time. For zero-downtime
> rotation, pre-cache the new JWKS at resource servers before switching, or accept a brief
> gap while cached JWKS entries expire (up to 1 hour due to `Cache-Control: max-age=3600`).
> Multi-key JWKS is not currently supported.

If `JWT_KEY_ID` is not set, it is automatically derived from the SHA-256 hash of the DER-encoded public key (base64url-encoded, 43 characters). This derivation is deterministic — the same key always produces the same `kid`.

---

## Token Lifetime Profiles

AuthGate assigns every OAuth client one of three **token lifetime presets** so admins can tune access and refresh token durations to each client's risk profile without touching the base JWT configuration. The preset is selectable from the admin UI (**Admin → OAuth Clients → Token Lifetime**) and recorded on the client as `token_profile`.

### Profiles

| Profile    | When to use                                               | Default access TTL      | Default refresh TTL               |
| ---------- | --------------------------------------------------------- | ----------------------- | --------------------------------- |
| `short`    | High-security apps (admin consoles, financial dashboards) | 15 min                  | 24 h                              |
| `standard` | Typical web/SPA clients (default for new clients)         | `JWT_EXPIRATION` (10 h) | `REFRESH_TOKEN_EXPIRATION` (30 d) |
| `long`     | CLI tools, IoT devices, long-lived background jobs        | 24 h                    | 90 d                              |

Defaults are overridable per environment via the `TOKEN_PROFILE_*` variables listed in [Environment Variables](#environment-variables).

### Hard caps

`JWT_EXPIRATION_MAX` and `REFRESH_TOKEN_EXPIRATION_MAX` bound every profile's TTL. The server refuses to start if any configured profile exceeds its cap — this guarantees that a stray env override cannot issue tokens longer than the operator intends.

### Jitter behavior

`JWT_EXPIRATION_JITTER` is applied only when the resolved access-token TTL matches the base `JWT_EXPIRATION` (the `standard`-profile default). Explicit `short`/`long` overrides — and a `standard` profile that has been explicitly diverged from the base config — use the profile's TTL exactly, with no jitter added. This keeps jitter working for the high-volume default path (preventing refresh thundering herds) while respecting operator-chosen short/long lifetimes precisely.

### Client Credentials independence

The `client_credentials` grant is governed by `CLIENT_CREDENTIALS_TOKEN_EXPIRATION` and **ignores** the client's TokenProfile. M2M tokens carry a larger blast radius than user-delegated tokens (no refresh, no user-revoke UI), so their lifetime is managed separately and is typically kept much shorter than user-facing tokens. If you need per-client M2M TTLs, open an issue — it will require a dedicated field on TokenProfile rather than overloading the existing access TTL.

### Changing a profile

Updates take effect on the **next token issuance or refresh**. Existing tokens retain the lifetime they were originally issued with; AuthGate does not retroactively shorten live tokens. Every TokenProfile change is recorded in the audit log at `WARNING` severity with the previous value (`previous_token_profile`) for forensic traceability.

---

## Caller-Supplied Extra Claims

OAuth clients can attach an arbitrary `map[string]any` of custom claims to issued JWTs by sending an `extra_claims` form parameter on `/oauth/token`. Enabled by default and applies to all four grant types (`authorization_code`, `urn:ietf:params:oauth:grant-type:device_code`, `client_credentials`, `refresh_token`).

```bash
curl -X POST https://authgate.example/oauth/token \
  -d 'grant_type=client_credentials' \
  -u 'CLIENT_ID:CLIENT_SECRET' \
  --data-urlencode 'extra_claims={"tenant":"acme","trace_id":"abc-123","feature_flags":["beta"]}'
```

The supplied JSON object is merged into the JWT alongside standard claims. Reserved JWT/OIDC claim keys (`iss`, `sub`, `exp`, `iat`, `jti`, `aud`, `nbf`, `type`, `scope`, `user_id`, `client_id`, `azp`, `amr`, `acr`, `auth_time`, `nonce`, `at_hash`, `project`, `service_account`) are rejected with `invalid_request` at the parser. As a supplementary guard, `generateJWT` also overwrites the standard claims it manages (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `type`, `scope`, `user_id`, `client_id`) and drops the OIDC-only ID-token keys (`nbf`, `azp`, `amr`, `acr`, `auth_time`, `nonce`, `at_hash`) that have no place in an access token — so a caller-supplied value for any of those cannot survive signing even if it bypasses the parser. System claims set on the OAuth client (`project`, `service_account`) override caller values on collision — admins always win.

### Configuration

| Variable                    | Default | Purpose                                                                                  |
| --------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `EXTRA_CLAIMS_ENABLED`      | `true`  | Master switch. Set to `false` to make any non-empty `extra_claims` parameter return 400. |
| `EXTRA_CLAIMS_MAX_RAW_SIZE` | `4096`  | Maximum raw JSON payload size in bytes. `0` disables the check.                          |
| `EXTRA_CLAIMS_MAX_KEYS`     | `16`    | Maximum number of top-level keys. `0` disables the check.                                |
| `EXTRA_CLAIMS_MAX_VAL_SIZE` | `512`   | Maximum JSON-encoded size of any single value in bytes. `0` disables the check.          |

### Stateless behaviour

Custom claims are **not persisted** server-side. To keep them on a refreshed token, the caller must re-supply `extra_claims` on every refresh request. Omitting the parameter on refresh produces a token with no caller claims (system claims like `project` / `service_account` still flow through from the OAuth client record).

### Trust model

The signature only proves AuthGate emitted these values, not that they are authoritative. Downstream resource servers must treat caller-supplied claims as **self-asserted** and apply their own access policies — never make authorization decisions on `extra_claims` values without independent verification. See [`docs/JWT_VERIFICATION.md`](JWT_VERIFICATION.md) for the full trust model.

---

## Default Test Data

The server initializes with default test accounts:

### User Account

- Username: `admin`
- Password: Set via `DEFAULT_ADMIN_PASSWORD` environment variable, or auto-generated 16-character random password (written to `authgate-credentials.txt` on first run)

### OAuth Client

- Name: `AuthGate CLI`
- Client ID: Auto-generated UUID (written to `authgate-credentials.txt`)

**⚠️ Security Warning:** Set a secure admin password via `DEFAULT_ADMIN_PASSWORD` environment variable. If not set, a random password will be generated and written to `authgate-credentials.txt` (mode 0600) on first run. Delete this file after retrieving the credentials.

---

## OAuth Third-Party Login

AuthGate supports OAuth 2.0 authentication with third-party providers, allowing users to sign in with their existing accounts from GitHub, Gitea, and other OAuth providers.

### Supported Providers

- **GitHub** - Sign in with GitHub accounts
- **Gitea** - Sign in with self-hosted or public Gitea instances
- **Microsoft Entra ID (Azure AD)** - Sign in with Microsoft work, school, or personal accounts
- **Extensible** - Easy to add GitLab, Google, or other OAuth 2.0 providers

### Key Features

- **Email-Based Account Linking**: Automatically links OAuth accounts to existing users with matching email addresses
- **Auto-Registration**: New users can be automatically created via OAuth login
- **Multiple Authentication Methods**: Users can have both password and OAuth authentication
- **Profile Sync**: Avatar and profile information synced from OAuth providers
- **Secure by Default**: CSRF protection via state parameter, TLS verification enabled

### Quick Setup

1. **Create OAuth Application** in your provider (GitHub/Gitea)
2. **Configure AuthGate** with client credentials:

```bash
# Enable GitHub OAuth
GITHUB_OAUTH_ENABLED=true
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
GITHUB_REDIRECT_URL=http://localhost:8080/auth/callback/github

# Enable Gitea OAuth
GITEA_OAUTH_ENABLED=true
GITEA_URL=https://gitea.example.com
GITEA_CLIENT_ID=your_client_id
GITEA_CLIENT_SECRET=your_client_secret
GITEA_REDIRECT_URL=http://localhost:8080/auth/callback/gitea

# Enable Microsoft Entra ID OAuth
MICROSOFT_OAUTH_ENABLED=true
MICROSOFT_TENANT_ID=common
MICROSOFT_CLIENT_ID=your_client_id
MICROSOFT_CLIENT_SECRET=your_client_secret
MICROSOFT_REDIRECT_URL=http://localhost:8080/auth/callback/microsoft
```

3. **Restart server** and visit `/login` to see OAuth buttons

### Authentication Scenarios

**Scenario 1: New User**

- User clicks "Sign in with GitHub"
- GitHub returns email: alice@example.com
- System creates new user with GitHub OAuth connection
- User is logged in

**Scenario 2: Existing User (Email Match)**

- User Bob already has account: bob@example.com
- Bob clicks "Sign in with GitHub"
- GitHub returns same email: bob@example.com
- System automatically links GitHub to Bob's account
- Bob can now login with either password or GitHub

**Scenario 3: Multiple OAuth Accounts**

- User can link multiple OAuth providers (GitHub + Gitea + Microsoft)
- All methods log into the same AuthGate account

### Security Considerations

- **HTTPS Required**: Always use HTTPS in production
- **Email Validation**: OAuth providers must return verified email addresses
- **TLS Verification**: Never set `OAUTH_INSECURE_SKIP_VERIFY=true` in production
- **Token Storage**: OAuth tokens stored in database (consider encryption at rest)

### Detailed Setup Guide

For complete setup instructions including:

- Step-by-step provider configuration
- Production deployment guidelines
- Troubleshooting common issues
- Adding custom OAuth providers

See [OAuth Setup Guide](OAUTH_SETUP.md)

---

## Service-to-Service Authentication

When AuthGate connects to external HTTP APIs (for authentication), you can secure these service-to-service communications with authentication headers.

### Why Service-to-Service Authentication?

External HTTP API providers (authentication services) need to verify that incoming requests are from a trusted AuthGate instance. Without authentication, these endpoints would be vulnerable to unauthorized access.

### Authentication Modes

AuthGate supports three authentication modes for securing HTTP API communications:

**1. None Mode (Default)**

No authentication headers are added. Suitable for development or when the external API is secured by other means (e.g., network isolation).

```bash
# No configuration needed - this is the default
HTTP_API_AUTH_MODE=none
```

**2. Simple Mode**

Adds a shared secret in a custom header (default: `X-API-Secret`). Quick to set up but less secure than HMAC.

```bash
HTTP_API_AUTH_MODE=simple
HTTP_API_AUTH_SECRET=your-shared-secret-here
HTTP_API_AUTH_HEADER=X-API-Secret  # Optional, default shown
```

**3. HMAC Mode (Recommended)**

Uses HMAC-SHA256 signature with timestamp validation to prevent replay attacks. Provides the highest security for production environments.

```bash
HTTP_API_AUTH_MODE=hmac
HTTP_API_AUTH_SECRET=your-hmac-secret-here
```

HMAC mode automatically adds these headers to each request:

- `X-Signature`: HMAC-SHA256 signature of `timestamp + method + path + body`
- `X-Timestamp`: Unix timestamp (validated within 5-minute window)
- `X-Nonce`: Unique request identifier

### Configuration

| Environment Variable   | Purpose                           |
| ---------------------- | --------------------------------- |
| `HTTP_API_AUTH_MODE`   | Auth mode for user authentication |
| `HTTP_API_AUTH_SECRET` | Shared secret for authentication  |
| `HTTP_API_AUTH_HEADER` | Custom header name (simple mode)  |

### Server-Side Verification Example

Your external API must verify incoming requests. Here's a Go example for HMAC verification:

```go
import httpclient "github.com/appleboy/go-httpclient"

// Initialize auth config (server side)
authConfig := httpclient.NewAuthConfig("hmac", "your-hmac-secret")

// Verify incoming request
err := authConfig.VerifyHMACSignature(req, 5*time.Minute)
if err != nil {
    http.Error(w, "Authentication failed", http.StatusUnauthorized)
    return
}
```

### Example: Securing External Authentication API

**Scenario**: Your company has a central authentication service that AuthGate should use for user login.

**Setup**:

1. Configure AuthGate to use external authentication with HMAC:

```bash
# .env file
AUTH_MODE=http_api
HTTP_API_URL=https://auth.company.com/api/verify
HTTP_API_AUTH_MODE=hmac
HTTP_API_AUTH_SECRET=shared-secret-between-services
```

2. Your authentication API validates the HMAC signature before processing login requests.

3. When users log into AuthGate, their credentials are forwarded to your API with HMAC signature verification.

---

## HTTP Retry with Exponential Backoff

AuthGate includes automatic HTTP retry capabilities for all external API communications (authentication and token operations) to improve reliability and resilience against transient network failures.

### Features

- **Automatic Retries**: Failed HTTP requests are automatically retried with configurable attempts
- **Exponential Backoff**: Retry delays increase exponentially to avoid overwhelming failing services
- **Smart Retry Logic**: Only retries on appropriate errors (network failures, 5xx errors, 429 rate limits)
- **Non-Blocking**: Retries respect context cancellation and timeouts

### Default Behavior

By default, AuthGate retries failed requests up to 3 times with the following pattern:

- **Initial delay**: 1 second
- **Maximum delay**: 10 seconds
- **Multiplier**: 2.0x (exponential backoff)

Example retry sequence:

1. First attempt fails → wait 1s
2. Second attempt fails → wait 2s
3. Third attempt fails → wait 4s
4. Fourth attempt fails → return error

### Automatic Retry Conditions

Requests are automatically retried on:

- Network errors (connection failures, timeouts, DNS issues)
- HTTP 5xx server errors (500, 502, 503, 504)
- HTTP 429 (Too Many Requests)

Requests are **not** retried on:

- HTTP 4xx client errors (except 429)
- HTTP 2xx/3xx successful responses
- Context cancellation or timeout

### Configuration

Configure retry behavior for each external service independently:

```bash
HTTP_API_MAX_RETRIES=5              # Maximum retry attempts (default: 3)
HTTP_API_RETRY_DELAY=2s             # Initial retry delay (default: 1s)
HTTP_API_MAX_RETRY_DELAY=30s        # Maximum retry delay (default: 10s)
```

### Disable Retries

To disable retries (not recommended for production):

```bash
HTTP_API_MAX_RETRIES=0
```

### Use Cases

**1. Handling Transient Network Issues**

Temporary network glitches are automatically handled without failing the entire request:

- Brief network interruptions
- DNS resolution delays
- Connection pool exhaustion

**2. Service Restarts**

When external services restart, AuthGate automatically retries until the service is available:

- Rolling deployments
- Service updates
- Container restarts

**3. Rate Limiting**

When external APIs return 429 (rate limit), AuthGate backs off and retries:

- Automatic backoff on rate limits
- Prevents cascading failures
- Respects service quotas

### Best Practices

1. **Production Settings**: Use default retry settings (3 retries) for most production scenarios
2. **High-Traffic Environments**: Consider increasing `MAX_RETRY_DELAY` to 30s-60s to avoid overwhelming recovering services
3. **Low-Latency Requirements**: Reduce `MAX_RETRIES` to 1-2 for time-sensitive operations
4. **Monitoring**: Track retry rates to identify unreliable external services
5. **Timeouts**: Ensure `HTTP_API_TIMEOUT` is set appropriately to account for retries

### Example: Aggressive Retry Configuration

For critical services where availability is paramount:

```bash
# Retry up to 10 times with longer delays
HTTP_API_MAX_RETRIES=10
HTTP_API_RETRY_DELAY=500ms
HTTP_API_MAX_RETRY_DELAY=60s
HTTP_API_TIMEOUT=120s  # Increase timeout to accommodate retries
```

### Example: Conservative Retry Configuration

For fast-fail scenarios where latency matters more than resilience:

```bash
# Retry only once with short delays
HTTP_API_MAX_RETRIES=1
HTTP_API_RETRY_DELAY=500ms
HTTP_API_MAX_RETRY_DELAY=2s
HTTP_API_TIMEOUT=15s
```

### Implementation Details

- Built using [go-httpretry v0.2.0](https://github.com/appleboy/go-httpretry)
- Retry logic wraps the authentication-enabled HTTP client
- All authentication headers (Simple, HMAC) are preserved across retries
- Request bodies are cloned for retries to avoid consumed stream issues

---

## User Cache

`GetUserByID` is called on **every protected request** — once by the `RequireAuth` middleware and once more by `RequireAdmin`. Without caching, each request incurs at least one synchronous DB round-trip. Under heavy traffic or DDoS conditions this translates directly into database pressure.

AuthGate ships with a built-in user cache (always enabled, no feature flag required) that absorbs these lookups before they reach the database.

### How It Works

The cache uses a **cache-aside pattern**:

1. On the first request for a user ID, the DB is queried and the result is stored in cache with a TTL
2. Subsequent requests within the TTL window are served entirely from cache
3. Cache entries are invalidated automatically whenever user data is mutated (OAuth sync, profile updates)

### Cache Backends

| Backend     | Env value          | Use case                                                                          |
| ----------- | ------------------ | --------------------------------------------------------------------------------- |
| Memory      | `memory` (default) | Single-instance, zero external dependencies                                       |
| Redis       | `redis`            | 2–5 pods, shared cache across instances                                           |
| Redis-aside | `redis-aside`      | 5+ pods, client-side caching with stampede protection — **requires Redis >= 7.0** |

### Configuration

```bash
# Cache backend: memory (default), redis, or redis-aside
USER_CACHE_TYPE=memory

# How long a cached user object is valid (default: 5m); must be > 0
# Shorter → password/role changes propagate faster
# Longer  → more aggressive DB protection
USER_CACHE_TTL=5m

# Client-side TTL for redis-aside mode only (default: 30s); must be > 0
USER_CACHE_CLIENT_TTL=30s

# Client-side cache size per connection in MB for redis-aside mode only (default: 32MB)
# Total memory per pod = cache_size × connections (~10 based on GOMAXPROCS) → default ~320MB
USER_CACHE_SIZE_PER_CONN=32
```

Redis-based backends also require the shared Redis settings:

```bash
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
```

### TTL Trade-offs

| TTL   | Behaviour                                                        |
| ----- | ---------------------------------------------------------------- |
| `1m`  | Role or password changes take effect within 1 minute             |
| `5m`  | Default — good balance between security and DB protection        |
| `15m` | Aggressive DB protection; suitable when user data rarely changes |

### Multi-Pod Recommendation

For Kubernetes or cloud deployments with multiple replicas:

```bash
# 2–5 pods: Redis shared cache
USER_CACHE_TYPE=redis
REDIS_ADDR=redis-service:6379

# 5+ pods or DDoS protection: redis-aside with client-side caching
USER_CACHE_TYPE=redis-aside
REDIS_ADDR=redis-service:6379
USER_CACHE_CLIENT_TTL=30s
USER_CACHE_SIZE_PER_CONN=32  # Adjust based on available memory per pod
```

> **Note**: `redis-aside` uses RESP3 client-side caching for automatic invalidation across all pods and requires **Redis >= 7.0**. If you are running an older Redis version, use `USER_CACHE_TYPE=redis` instead. Memory usage per pod is `USER_CACHE_SIZE_PER_CONN × ~10 connections` (default ~320MB). Adjust `USER_CACHE_SIZE_PER_CONN` if memory is constrained.

---

## Client Cache

Every OAuth flow (device code, authorization code, token exchange, client credentials) queries the `OAuthApplication` record to validate the client. Caching these lookups reduces database pressure on busy deployments.

The cache is always enabled with no feature flag required. Mutations (create, update, delete, secret regeneration, approve/reject) always invalidate the cache entry immediately.

### How It Works

The cache uses a **cache-aside pattern**:

1. On the first request for a client ID, the DB is queried and the result is stored in cache with a TTL
2. Client secrets are **stripped before caching** (defense-in-depth — secrets are never stored in the cache backend)
3. Cache entries are invalidated immediately on any write operation (create, update, delete, secret rotation)

### Cache Backends

| Backend     | Env value          | Use case                                                                          |
| ----------- | ------------------ | --------------------------------------------------------------------------------- |
| Memory      | `memory` (default) | Single-instance, zero external dependencies                                       |
| Redis       | `redis`            | 2–5 pods, shared cache across instances                                           |
| Redis-aside | `redis-aside`      | 5+ pods, client-side caching with stampede protection — **requires Redis >= 7.0** |

### Configuration

```bash
# Cache backend: memory (default), redis, or redis-aside
CLIENT_CACHE_TYPE=memory

# How long a cached client record is valid (default: 5m); must be > 0
# Mutations always invalidate immediately, so this is only a fallback TTL.
CLIENT_CACHE_TTL=5m

# Client-side TTL for redis-aside mode only (default: 30s); must be > 0
CLIENT_CACHE_CLIENT_TTL=30s

# Client-side cache size per connection in MB for redis-aside mode only (default: 32MB)
# Total memory per pod = cache_size × connections (~10 based on GOMAXPROCS) → default ~320MB
CLIENT_CACHE_SIZE_PER_CONN=32
```

Redis-based backends also require the shared Redis settings:

```bash
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
```

### Multi-Pod Recommendation

```bash
# 2–5 pods: Redis shared cache
CLIENT_CACHE_TYPE=redis
REDIS_ADDR=redis-service:6379

# 5+ pods or DDoS protection: redis-aside with client-side caching
CLIENT_CACHE_TYPE=redis-aside
REDIS_ADDR=redis-service:6379
CLIENT_CACHE_CLIENT_TTL=30s
CLIENT_CACHE_SIZE_PER_CONN=32  # Adjust based on available memory per pod
```

> **Note**: `redis-aside` uses RESP3 client-side caching for automatic invalidation across all pods and requires **Redis >= 7.0**. Memory usage per pod is `CLIENT_CACHE_SIZE_PER_CONN × ~10 connections` (default ~320MB).

---

## Token Cache

`/oauth/tokeninfo` and every request protected by token-based auth call `GetAccessTokenByHash`, which hits the database on every validation. The token cache absorbs these lookups, reducing DB load significantly on high-traffic deployments.

The token cache is **disabled by default** (`TOKEN_CACHE_ENABLED=false`). Enable it for production deployments with significant token validation traffic.

### How It Works

The cache uses a **cache-aside pattern**:

1. On the first validation of a token hash, the DB is queried and the result is stored in cache with a TTL
2. Subsequent validations within the TTL window are served from cache
3. Token revocation, rotation, and status changes always **explicitly invalidate** the cache entry — the TTL is a fallback only

### Cache Backends

| Backend     | Env value          | Use case                                                                                   |
| ----------- | ------------------ | ------------------------------------------------------------------------------------------ |
| Memory      | `memory` (default) | Single-instance, zero external dependencies                                                |
| Redis       | `redis`            | 2–5 pods, shared cache across instances                                                    |
| Redis-aside | `redis-aside`      | 5+ pods, client-side caching with RESP3 real-time invalidation — **requires Redis >= 7.0** |

### Configuration

```bash
# Enable token verification cache (default: false)
TOKEN_CACHE_ENABLED=false

# Cache backend: memory (default), redis, or redis-aside
TOKEN_CACHE_TYPE=memory

# Cache lifetime (default: 10h — matches JWT_EXPIRATION)
# Revocation uses explicit cache invalidation; this TTL is a fallback for rare missed invalidations.
TOKEN_CACHE_TTL=10h

# Client-side TTL for redis-aside mode only (default: 1h)
# RESP3 handles real-time invalidation; this TTL is a safety net for missed notifications.
TOKEN_CACHE_CLIENT_TTL=1h

# Client-side cache size per connection in MB for redis-aside mode only (default: 32MB)
# Total memory per pod = cache_size × connections (~10 based on GOMAXPROCS) → default ~320MB
TOKEN_CACHE_SIZE_PER_CONN=32
```

Redis-based backends also require the shared Redis settings:

```bash
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
```

### TTL Trade-offs

| Setting                     | Behaviour                                                                       |
| --------------------------- | ------------------------------------------------------------------------------- |
| `TOKEN_CACHE_TTL=10h`       | Default — matches JWT expiry; cached tokens expire naturally alongside JWT      |
| `TOKEN_CACHE_CLIENT_TTL=1h` | redis-aside client-side TTL; RESP3 invalidation fires immediately on revocation |

### Multi-Pod Recommendation

```bash
# Enable with Redis for multi-pod deployments
TOKEN_CACHE_ENABLED=true
TOKEN_CACHE_TYPE=redis
REDIS_ADDR=redis-service:6379

# Or redis-aside for real-time invalidation across all pods (requires Redis >= 7.0)
TOKEN_CACHE_ENABLED=true
TOKEN_CACHE_TYPE=redis-aside
REDIS_ADDR=redis-service:6379
TOKEN_CACHE_CLIENT_TTL=1h
TOKEN_CACHE_SIZE_PER_CONN=32
```

> **Note**: `redis-aside` uses RESP3 client-side caching with **real-time invalidation** — when a token is revoked, all pods drop their client-side cache entry immediately via RESP3 push notifications. This requires **Redis >= 7.0**. Memory usage per pod is `TOKEN_CACHE_SIZE_PER_CONN × ~10 connections` (default ~320MB).

---

## Rate Limiting

AuthGate includes built-in rate limiting to protect against brute force attacks, credential stuffing, and API abuse. The rate limiting system is production-ready with support for both single-instance and distributed deployments.

### Key Features

- **Dual Storage Backends**:
  - **Memory Store**: Fast, in-memory storage for single-instance deployments
  - **Redis Store**: Distributed storage for multi-pod Kubernetes/cloud deployments
- **Per-Endpoint Configuration**: Different rate limits for different endpoints
- **IP-Based Tracking**: Tracks requests per client IP address
- **Hot Configuration**: Enable/disable without code changes
- **Graceful Degradation**: Automatic fallback when Redis is unavailable

### Quick Start

**Single Instance (Default):**

```bash
# Default configuration - rate limiting enabled with memory store
./bin/authgate server
```

**Multi-Pod with Redis:**

```bash
# .env
ENABLE_RATE_LIMIT=true
RATE_LIMIT_STORE=redis
REDIS_ADDR=redis-service:6379
REDIS_PASSWORD=your-password
```

**Default Rate Limits:**

| Endpoint                  | Limit      | Purpose                              |
| ------------------------- | ---------- | ------------------------------------ |
| `POST /login`             | 5 req/min  | Prevent password brute force         |
| `POST /oauth/device/code` | 10 req/min | Prevent device code spam             |
| `POST /oauth/token`       | 20 req/min | Allow polling while preventing abuse |
| `POST /device/verify`     | 10 req/min | Prevent user code guessing           |
| `POST /oauth/register`    | 5 req/min  | Prevent registration spam            |
| `POST /oauth/introspect`  | 20 req/min | Prevent client secret brute force    |

### Configuration Guide

All rate limits are configurable via environment variables:

```bash
# Enable/disable rate limiting
ENABLE_RATE_LIMIT=true              # Default: true

# Storage backend
RATE_LIMIT_STORE=memory             # Options: memory, redis

# Redis configuration (only when RATE_LIMIT_STORE=redis)
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0

# Per-endpoint limits (requests per minute)
LOGIN_RATE_LIMIT=5
DEVICE_CODE_RATE_LIMIT=10
TOKEN_RATE_LIMIT=20
DEVICE_VERIFY_RATE_LIMIT=10
DYNAMIC_CLIENT_REGISTRATION_RATE_LIMIT=5
INTROSPECT_RATE_LIMIT=20
```

**📖 For complete documentation, deployment scenarios, and troubleshooting, see [RATE_LIMITING.md](RATE_LIMITING.md)**

---

## CORS (Cross-Origin Resource Sharing)

When building a Single-Page Application (SPA) or mobile app that calls AuthGate's OAuth API endpoints from a different origin, you need to enable CORS. By default, CORS is **disabled** — enabling it only affects `/oauth/*` API endpoints (token, device code, introspect, revoke, userinfo). HTML page endpoints are never affected.

### Quick Start

```bash
# .env
CORS_ENABLED=true
CORS_ALLOWED_ORIGINS=http://localhost:3000,https://app.example.com
```

### Configuration

| Variable               | Default                             | Description                                 |
| ---------------------- | ----------------------------------- | ------------------------------------------- |
| `CORS_ENABLED`         | `false`                             | Enable CORS for API endpoints               |
| `CORS_ALLOWED_ORIGINS` | _(none)_                            | Comma-separated list of allowed origins     |
| `CORS_ALLOWED_METHODS` | `GET,POST,PUT,DELETE,OPTIONS`       | Allowed HTTP methods                        |
| `CORS_ALLOWED_HEADERS` | `Origin,Content-Type,Authorization` | Allowed request headers                     |
| `CORS_MAX_AGE`         | `12h`                               | How long browsers cache preflight responses |

### How It Works

- **Preflight requests** (`OPTIONS`) are handled automatically by the CORS middleware and return the appropriate `Access-Control-Allow-*` headers.
- **Credentials** (`cookies`, `Authorization` header) are allowed — `Access-Control-Allow-Credentials: true` is set so token introspection and authenticated requests work from browser JS.
- **Disallowed origins** receive a `403 Forbidden` response with no CORS headers.
- **Same-origin requests** (no `Origin` header) are unaffected.

### Production Notes

- Only list origins you trust — avoid using `*` (wildcard) with credentials.
- The CORS middleware is applied **only** to the `/oauth/*` route group, not to login pages, admin UI, or static assets.
- For maximum security, set `CORS_ALLOWED_ORIGINS` to the exact origins of your frontend applications.

---

**Next Steps:**

- [Architecture Guide](ARCHITECTURE.md) - Understand the system design
- [Deployment Guide](DEPLOYMENT.md) - Deploy to production
- [Security Guide](SECURITY.md) - Security best practices
