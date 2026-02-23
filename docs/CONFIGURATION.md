# Configuration Guide

This guide covers all configuration options for AuthGate, including environment variables, secrets management, and advanced features.

## Table of Contents

- [Environment Variables](#environment-variables)
- [Bootstrap and Shutdown Timeouts](#bootstrap-and-shutdown-timeouts)
- [Generate Strong Secrets](#generate-strong-secrets)
- [Default Test Data](#default-test-data)
- [OAuth Third-Party Login](#oauth-third-party-login)
- [Pluggable Token Providers](#pluggable-token-providers)
- [Service-to-Service Authentication](#service-to-service-authentication)
- [HTTP Retry with Exponential Backoff](#http-retry-with-exponential-backoff)
- [Rate Limiting](#rate-limiting)

---

## Environment Variables

Create a `.env` file in the project root:

```bash
# Server Configuration
SERVER_ADDR=:8080                # Listen address (e.g., :8080, 0.0.0.0:8080)
BASE_URL=http://localhost:8080   # Public URL for verification_uri

# Security - CHANGE THESE IN PRODUCTION!
JWT_SECRET=your-256-bit-secret-change-in-production       # HMAC-SHA256 signing key
SESSION_SECRET=session-secret-change-in-production        # Cookie encryption key

# Database
DATABASE_DRIVER=sqlite           # Database driver: "sqlite" or "postgres"
DATABASE_DSN=oauth.db            # Connection string (file path for SQLite, DSN for PostgreSQL)

# PostgreSQL Example:
# DATABASE_DRIVER=postgres
# DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=disable"

# Default Admin User
# Set a custom password for the default admin user created on first startup
# If not set, a random 16-character password will be generated and logged
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

# Token Provider Mode
# Options: local, http_api
# Default: local
TOKEN_PROVIDER_MODE=local

# HTTP API Token Provider (when TOKEN_PROVIDER_MODE=http_api)
# External token service will handle JWT generation and validation
TOKEN_API_URL=https://token.example.com/api
TOKEN_API_TIMEOUT=10s
TOKEN_API_INSECURE_SKIP_VERIFY=false

# Token API Retry Configuration
# Automatic retry with exponential backoff for failed requests
TOKEN_API_MAX_RETRIES=3          # Maximum retry attempts (default: 3, set 0 to disable)
TOKEN_API_RETRY_DELAY=1s         # Initial retry delay (default: 1s)
TOKEN_API_MAX_RETRY_DELAY=10s    # Maximum retry delay (default: 10s)

# Refresh Token Configuration
REFRESH_TOKEN_EXPIRATION=720h        # Refresh token lifetime (default: 30 days)
ENABLE_REFRESH_TOKENS=true          # Feature flag to enable/disable refresh tokens
ENABLE_TOKEN_ROTATION=false         # Enable rotation mode (default: fixed mode)

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

# Audit Logging
# Comprehensive audit logging for security and compliance
ENABLE_AUDIT_LOGGING=true               # Enable audit logging (default: true)
AUDIT_LOG_RETENTION=2160h               # Retention period: 90 days (default: 90 days = 2160h)
AUDIT_LOG_BUFFER_SIZE=1000              # Async buffer size (default: 1000)
AUDIT_LOG_CLEANUP_INTERVAL=24h          # Cleanup frequency (default: 24h)
```

---

## Bootstrap and Shutdown Timeouts

AuthGate supports configurable timeout durations for all lifecycle operations, enabling production tuning and graceful degradation.

### Overview

All timeout operations share a unified context flow from the graceful shutdown manager:
- **Initialization timeouts**: Control how long to wait for database, Redis, and cache connections during startup
- **Shutdown timeouts**: Control how long to wait for graceful cleanup of resources
- **Cancellation support**: All operations can be interrupted with Ctrl+C without hanging

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
- **Shutdown**: If a timeout is exceeded, the operation is forcefully terminated
- **Cancellation**: Pressing Ctrl+C cancels all in-progress operations via context
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

## Default Test Data

The server initializes with default test accounts:

### User Account

- Username: `admin`
- Password: Set via `DEFAULT_ADMIN_PASSWORD` environment variable, or auto-generated 16-character random password (shown in server logs on first run)

### OAuth Client

- Name: `AuthGate CLI`
- Client ID: Auto-generated UUID (shown in server logs)

**⚠️ Security Warning:** Set a secure admin password via `DEFAULT_ADMIN_PASSWORD` environment variable. If not set, a random password will be generated and logged on first run.

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

## Pluggable Token Providers

AuthGate supports **pluggable token providers** for JWT generation and validation, allowing you to delegate token operations to external services while maintaining local token management.

### Architecture

- **Token Generation & Validation**: Can be handled locally or by external HTTP API
- **Local Storage**: Token records are always stored in local database for management (revocation, listing, auditing)
- **Configuration**: Global mode selection via `TOKEN_PROVIDER_MODE` environment variable

### Token Provider Modes

**1. Local Mode (Default)**

Uses local JWT secret for token signing and verification:

```bash
TOKEN_PROVIDER_MODE=local  # Default, can be omitted
```

- JWT signed with HMAC-SHA256
- Uses `JWT_SECRET` from environment
- No external dependencies
- Best for: Self-contained deployments

**2. HTTP API Mode**

Delegates JWT generation and validation to external service:

```bash
TOKEN_PROVIDER_MODE=http_api
TOKEN_API_URL=https://token-service.example.com/api
TOKEN_API_TIMEOUT=10s
TOKEN_API_INSECURE_SKIP_VERIFY=false  # Set true only for dev/testing
```

- External service generates and validates JWTs
- Local database still stores token records
- Supports custom signing algorithms (RS256, ES256, etc.)
- Best for: Centralized token services, advanced key management

### HTTP API Contract

When using `TOKEN_PROVIDER_MODE=http_api`, your token service must implement:

**Token Generation Endpoint:** `POST {TOKEN_API_URL}/generate`

Request:

```json
{
  "user_id": "user-uuid",
  "client_id": "client-uuid",
  "scopes": "read write",
  "expires_in": 3600
}
```

Response:

```json
{
  "success": true,
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "claims": {
    "custom_claim": "value"
  }
}
```

**Token Validation Endpoint:** `POST {TOKEN_API_URL}/validate`

Request:

```json
{
  "token": "eyJhbGc..."
}
```

Response (Valid):

```json
{
  "valid": true,
  "user_id": "user-uuid",
  "client_id": "client-uuid",
  "scopes": "read write",
  "expires_at": 1736899200,
  "claims": {
    "custom_claim": "value"
  }
}
```

Response (Invalid):

```json
{
  "valid": false,
  "message": "Token expired or invalid"
}
```

### Why Local Storage is Retained

Even when using external token providers, AuthGate stores token records locally for:

1. **Revocation**: Users can revoke tokens via `/account/sessions` or `/oauth/revoke`
2. **Management**: Users can list their active sessions
3. **Auditing**: Track when and for which clients tokens were issued
4. **Client Association**: Link tokens to OAuth clients

### Use Cases

**Local Mode:**

- Self-hosted deployments
- Simple setups
- When you don't need advanced key management

**HTTP API Mode:**

- Centralized token services across multiple apps
- Advanced key rotation policies
- Custom JWT signing algorithms (RS256, ES256)
- Compliance requirements for token generation
- Integration with existing IAM systems

### Migration Path

1. Start with `TOKEN_PROVIDER_MODE=local` (default)
2. Test thoroughly
3. Set up external token service
4. Switch to `TOKEN_PROVIDER_MODE=http_api`
5. Monitor logs for errors
6. Can rollback to local mode without data loss

---

## Service-to-Service Authentication

When AuthGate connects to external HTTP APIs (for authentication or token operations), you can secure these service-to-service communications with authentication headers.

### Why Service-to-Service Authentication?

External HTTP API providers (authentication and token services) need to verify that incoming requests are from a trusted AuthGate instance. Without authentication, these endpoints would be vulnerable to unauthorized access.

### Authentication Modes

AuthGate supports three authentication modes for securing HTTP API communications:

**1. None Mode (Default)**

No authentication headers are added. Suitable for development or when the external API is secured by other means (e.g., network isolation).

```bash
# No configuration needed - this is the default
HTTP_API_AUTH_MODE=none
TOKEN_API_AUTH_MODE=none
```

**2. Simple Mode**

Adds a shared secret in a custom header (default: `X-API-Secret`). Quick to set up but less secure than HMAC.

```bash
# HTTP API Authentication
HTTP_API_AUTH_MODE=simple
HTTP_API_AUTH_SECRET=your-shared-secret-here
HTTP_API_AUTH_HEADER=X-API-Secret  # Optional, default shown

# Token API Authentication
TOKEN_API_AUTH_MODE=simple
TOKEN_API_AUTH_SECRET=your-token-secret-here
TOKEN_API_AUTH_HEADER=X-API-Secret  # Optional, default shown
```

**3. HMAC Mode (Recommended)**

Uses HMAC-SHA256 signature with timestamp validation to prevent replay attacks. Provides the highest security for production environments.

```bash
# HTTP API Authentication
HTTP_API_AUTH_MODE=hmac
HTTP_API_AUTH_SECRET=your-hmac-secret-here

# Token API Authentication
TOKEN_API_AUTH_MODE=hmac
TOKEN_API_AUTH_SECRET=your-hmac-token-secret
```

HMAC mode automatically adds these headers to each request:

- `X-Signature`: HMAC-SHA256 signature of `timestamp + method + path + body`
- `X-Timestamp`: Unix timestamp (validated within 5-minute window)
- `X-Nonce`: Unique request identifier

### Configuration per Service

Authentication is configured **separately** for each external service:

| Environment Variable    | Purpose                           | Service       |
| ----------------------- | --------------------------------- | ------------- |
| `HTTP_API_AUTH_MODE`    | Auth mode for user authentication | HTTP API Auth |
| `HTTP_API_AUTH_SECRET`  | Shared secret for authentication  | HTTP API Auth |
| `HTTP_API_AUTH_HEADER`  | Custom header name (simple mode)  | HTTP API Auth |
| `TOKEN_API_AUTH_MODE`   | Auth mode for token operations    | Token API     |
| `TOKEN_API_AUTH_SECRET` | Shared secret for token API       | Token API     |
| `TOKEN_API_AUTH_HEADER` | Custom header name (simple mode)  | Token API     |

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

**HTTP API Authentication:**

```bash
HTTP_API_MAX_RETRIES=5              # Maximum retry attempts (default: 3)
HTTP_API_RETRY_DELAY=2s             # Initial retry delay (default: 1s)
HTTP_API_MAX_RETRY_DELAY=30s        # Maximum retry delay (default: 10s)
```

**Token API:**

```bash
TOKEN_API_MAX_RETRIES=5             # Maximum retry attempts (default: 3)
TOKEN_API_RETRY_DELAY=2s            # Initial retry delay (default: 1s)
TOKEN_API_MAX_RETRY_DELAY=30s       # Maximum retry delay (default: 10s)
```

### Disable Retries

To disable retries (not recommended for production):

```bash
HTTP_API_MAX_RETRIES=0
TOKEN_API_MAX_RETRIES=0
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
5. **Timeouts**: Ensure `HTTP_API_TIMEOUT` and `TOKEN_API_TIMEOUT` are set appropriately to account for retries

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
```

**📖 For complete documentation, deployment scenarios, and troubleshooting, see [RATE_LIMITING.md](RATE_LIMITING.md)**

---

**Next Steps:**

- [Architecture Guide](ARCHITECTURE.md) - Understand the system design
- [Deployment Guide](DEPLOYMENT.md) - Deploy to production
- [Security Guide](SECURITY.md) - Security best practices
