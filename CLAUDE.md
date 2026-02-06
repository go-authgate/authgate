# CLAUDE.md

This file provides guidance to [Claude Code](https://claude.ai/code) when working with code in this repository.

## Project Overview

AuthGate is an OAuth 2.0 Device Authorization Grant (RFC 8628) server built with Go and Gin. It enables CLI tools to authenticate users without embedding client secrets.

## Common Commands

```bash
# Build
make build              # Build to bin/authgate with version info in LDFLAGS

# Run
./bin/authgate -v       # Show version information
./bin/authgate -h       # Show help
./bin/authgate server   # Start the OAuth server

# Test & Lint
make test               # Run tests with coverage report (outputs coverage.txt)
make lint               # Run golangci-lint (auto-installs if missing)
make fmt                # Format code with golangci-lint fmt

# Cross-compile (outputs to release/<os>/<arch>/)
make build_linux_amd64  # CGO_ENABLED=0 for static binary
make build_linux_arm64  # CGO_ENABLED=0 for static binary

# Clean
make clean              # Remove bin/, release/, coverage.txt

# Docker
docker build -f docker/Dockerfile -t authgate .
```

## Architecture

### Device Authorization Flow

1. CLI calls `POST /oauth/device/code` → receives device_code + user_code + verification_uri
2. User visits `/device` in browser, must login first if not authenticated
3. User submits user_code via `POST /device/verify` → device code marked as authorized
4. CLI polls `POST /oauth/token` with device_code every 5s → receives access_token + refresh_token
5. When access_token expires, CLI uses `grant_type=refresh_token` to get new token

### Layers (dependency injection pattern)

- `main.go` - Wires up store → auth providers → token providers → services → handlers
- `config/` - Loads .env via godotenv, provides Config struct with defaults
- `store/` - GORM-based data access layer, supports SQLite and PostgreSQL
  - `driver.go` - Database driver factory using map-based pattern (no if-else)
  - `sqlite.go` - Store implementation and database operations (driver-agnostic)
- `auth/` - Authentication providers (LocalAuthProvider, HTTPAPIAuthProvider)
- `token/` - Token providers (LocalTokenProvider, HTTPTokenProvider)
  - `types.go` - Shared data structures (TokenResult, TokenValidationResult)
  - `errors.go` - Provider-level error definitions
  - `local.go` - Local JWT provider (HMAC-SHA256)
  - `http_api.go` - External HTTP API token provider
- `services/` - Business logic (UserService, DeviceService, TokenService)
- `handlers/` - HTTP handlers (AuthHandler, DeviceHandler, TokenHandler)
- `models/` - GORM models (User, OAuthClient, DeviceCode, AccessToken)
- `middleware/` - Gin middleware (auth.go: RequireAuth checks session for user_id)

### Key Features

**Pluggable Authentication**

- Supports local (database) and external HTTP API authentication
- Per-user authentication routing based on `auth_source` field (hybrid mode)
- Configured via `AUTH_MODE` env var (`local` or `http_api`)
- Default admin user always uses local auth as failsafe

**Pluggable Token Providers**

- Supports local JWT (HMAC-SHA256) and external HTTP API token services
- Configured via `TOKEN_PROVIDER_MODE` env var (`local` or `http_api`)
- Token records always stored in local database for management
- LocalTokenProvider: Uses golang-jwt/jwt library
- HTTPTokenProvider: Delegates to external API, supports custom signing algorithms (RS256, ES256)

**Refresh Tokens (RFC 6749)**

- Two modes: Fixed (reusable) and Rotation (one-time use)
- Unified storage: Both access and refresh tokens in `AccessToken` table with `token_category` field
- Token family tracking via `parent_token_id` for audit trails
- Status management: `active`, `disabled`, or `revoked`
- Enable rotation mode via `ENABLE_TOKEN_ROTATION=true`

**Rate Limiting**

- IP-based rate limiting with configurable per-endpoint limits
- Two storage backends: Memory (single instance) or Redis (multi-pod)
- Built on github.com/ulule/limiter/v3 with sliding window algorithm
- Protects: /login (5 req/min), /oauth/device/code (10 req/min), /oauth/token (20 req/min), /device/verify (10 req/min)
- Enable/disable via `ENABLE_RATE_LIMIT` env var

**Audit Logging**

- Tracks authentication, device authorization, token operations, admin actions, security events
- Asynchronous batch writes (every 1s or 100 records) for minimal performance impact
- Automatic sensitive data masking (passwords, tokens, secrets)
- Event types: AUTHENTICATION*\*, DEVICE_CODE*_, TOKEN\__, CLIENT\_\*, RATE_LIMIT_EXCEEDED
- Severity levels: INFO, WARNING, ERROR, CRITICAL
- Web interface at `/admin/audit` with filtering and CSV export

**OAuth Provider Support**

- Microsoft Entra ID (Azure AD), GitHub, Gitea
- Auto-registration of users (configurable via `OAUTH_AUTO_REGISTER`)
- Uses OAuth 2.0 authorization code flow

**Service-to-Service Authentication**

- Three modes: `none` (default), `simple` (shared secret), `hmac` (signature-based)
- Protects communication with external auth/token APIs
- HMAC mode provides replay attack protection with timestamp validation

### Key Implementation Details

- Device codes expire after 30min (configurable via `DeviceCodeExpiration`)
- User codes: 8-char uppercase alphanumeric, normalized (uppercase + dashes removed)
- JWTs signed with HMAC-SHA256, expire after 1 hour
- Sessions: encrypted cookies (gin-contrib/sessions), configurable expiry (default: 1 hour)
- Polling interval: 5 seconds
- Templates and static files embedded via `//go:embed`
- Error handling: Services return typed errors, handlers convert to RFC 8628 OAuth responses

### Key Endpoints

- `GET /health` - Health check with database connection test
- `POST /oauth/device/code` - CLI requests device+user codes
- `POST /oauth/token` - Token endpoint (grant_type: device_code or refresh_token)
- `GET /oauth/tokeninfo` - Verify JWT validity
- `POST /oauth/revoke` - Revoke tokens (RFC 7009)
- `GET /device` - User authorization page (protected)
- `POST /device/verify` - User submits code to authorize device (protected)
- `GET|POST /login` - User authentication
- `GET /logout` - Clear session
- `GET /admin/audit` - View audit logs (admin only)

## Environment Variables

| Variable                     | Default               | Description                                             |
| ---------------------------- | --------------------- | ------------------------------------------------------- |
| SERVER_ADDR                  | :8080                 | Listen address                                          |
| BASE_URL                     | http://localhost:8080 | Public URL for verification_uri                         |
| JWT_SECRET                   | (default)             | JWT signing key (local mode)                            |
| SESSION_SECRET               | (default)             | Cookie encryption key                                   |
| SESSION_MAX_AGE              | 3600                  | Session lifetime in seconds (1 hour default)            |
| DATABASE_DRIVER              | sqlite                | Database driver ("sqlite" or "postgres")                |
| DATABASE_DSN                 | oauth.db              | Connection string                                       |
| **AUTH_MODE**                | local                 | Authentication mode: `local` or `http_api`              |
| HTTP_API_URL                 | (none)                | External auth API endpoint                              |
| HTTP_API_TIMEOUT             | 10s                   | HTTP API request timeout                                |
| HTTP_API_AUTH_MODE           | none                  | Service auth: `none`, `simple`, or `hmac`               |
| HTTP_API_AUTH_SECRET         | (none)                | Shared secret for service authentication                |
| **TOKEN_PROVIDER_MODE**      | local                 | Token provider: `local` or `http_api`                   |
| TOKEN_API_URL                | (none)                | External token API endpoint                             |
| TOKEN_API_TIMEOUT            | 10s                   | Token API request timeout                               |
| TOKEN_API_AUTH_MODE          | none                  | Service auth: `none`, `simple`, or `hmac`               |
| TOKEN_API_AUTH_SECRET        | (none)                | Shared secret for service authentication                |
| **REFRESH_TOKEN_EXPIRATION** | 720h                  | Refresh token lifetime (30 days)                        |
| **ENABLE_REFRESH_TOKENS**    | true                  | Enable refresh tokens                                   |
| **ENABLE_TOKEN_ROTATION**    | false                 | Enable rotation mode (default: fixed mode)              |
| **ENABLE_RATE_LIMIT**        | true                  | Enable rate limiting                                    |
| **RATE_LIMIT_STORE**         | memory                | Storage backend: `memory` or `redis`                    |
| LOGIN_RATE_LIMIT             | 5                     | Requests per minute for /login                          |
| DEVICE_CODE_RATE_LIMIT       | 10                    | Requests per minute for /oauth/device/code              |
| TOKEN_RATE_LIMIT             | 20                    | Requests per minute for /oauth/token                    |
| DEVICE_VERIFY_RATE_LIMIT     | 10                    | Requests per minute for /device/verify                  |
| REDIS_ADDR                   | localhost:6379        | Redis server address (when RATE_LIMIT_STORE=redis)      |
| REDIS_PASSWORD               | (empty)               | Redis password                                          |
| REDIS_DB                     | 0                     | Redis database number                                   |
| **ENABLE_AUDIT_LOGGING**     | true                  | Enable audit logging                                    |
| AUDIT_LOG_RETENTION          | 2160h                 | Retention period (90 days)                              |
| AUDIT_LOG_BUFFER_SIZE        | 1000                  | Async buffer size                                       |
| AUDIT_LOG_CLEANUP_INTERVAL   | 24h                   | Cleanup frequency                                       |
| **MICROSOFT_OAUTH_ENABLED**  | false                 | Enable Microsoft Entra ID OAuth                         |
| MICROSOFT_TENANT_ID          | common                | Tenant: `common`, `organizations`, `consumers`, or UUID |
| MICROSOFT_CLIENT_ID          | (none)                | Microsoft OAuth client ID                               |
| MICROSOFT_CLIENT_SECRET      | (none)                | Microsoft OAuth client secret                           |
| **GITHUB_OAUTH_ENABLED**     | false                 | Enable GitHub OAuth                                     |
| GITHUB_CLIENT_ID             | (none)                | GitHub OAuth client ID                                  |
| GITHUB_CLIENT_SECRET         | (none)                | GitHub OAuth client secret                              |
| **GITEA_OAUTH_ENABLED**      | false                 | Enable Gitea OAuth                                      |
| GITEA_URL                    | (none)                | Gitea instance URL                                      |
| GITEA_CLIENT_ID              | (none)                | Gitea OAuth client ID                                   |
| GITEA_CLIENT_SECRET          | (none)                | Gitea OAuth client secret                               |
| OAUTH_AUTO_REGISTER          | true                  | Allow OAuth auto-registration                           |
| OAUTH_TIMEOUT                | 15s                   | OAuth HTTP client timeout                               |

## Default Test Data

Seeded automatically on first run (store/sqlite.go:seedData):

- User: `admin` / `<random_password>` (16-character random password, logged at startup, bcrypt hashed)
- Client: `AuthGate CLI` (client_id is auto-generated UUID, logged at startup)

## Example CLI Client

`_example/authgate-cli/` contains a demo CLI that demonstrates the device flow:

```bash
cd _example/authgate-cli
cp .env.example .env      # Add CLIENT_ID from server logs
go run main.go
```

## External API Integration

### HTTP API Authentication

When `AUTH_MODE=http_api`, AuthGate delegates authentication to external API:

- Request: POST to `HTTP_API_URL` with `{"username": "...", "password": "..."}`
- Response: `{"success": true, "user_id": "...", "email": "...", "full_name": "..."}`
- First login auto-creates user with `auth_source="http_api"`
- Default admin user always uses local auth (failsafe)

### HTTP API Token Provider

When `TOKEN_PROVIDER_MODE=http_api`, AuthGate delegates token generation/validation to external API:

- Generation: POST to `{TOKEN_API_URL}/generate` with user_id, client_id, scopes, expires_in
- Validation: POST to `{TOKEN_API_URL}/validate` with token
- Token records still saved to local database for revocation/management

### Service-to-Service Authentication

Secure communication with external APIs using `HTTP_API_AUTH_MODE` / `TOKEN_API_AUTH_MODE`:

- `none` - No authentication (default, trusted networks only)
- `simple` - Shared secret header (e.g., `X-API-Secret: your-secret`)
- `hmac` - HMAC-SHA256 signature with timestamp validation (production recommended)

## Coding Conventions

- Use `http.StatusOK`, `http.StatusBadRequest`, etc. instead of numeric status codes
- Services return typed errors, handlers convert to appropriate HTTP responses
- GORM models use `gorm.Model` for CreatedAt/UpdatedAt/DeletedAt
- Handlers accept both form-encoded and JSON request bodies where applicable
- All static assets and templates are embedded via `//go:embed` for single-binary deployment
- **No Interfaces**: Direct struct dependency injection (project convention)
- **Audit Logging**: Services that modify data should log audit events
  - Use `auditService.Log()` for normal events (async, non-blocking)
  - Use `auditService.LogSync()` for critical security events (synchronous)
  - Sensitive data is automatically masked by AuditService (passwords, tokens, secrets)
- **IMPORTANT**: Before committing changes:
  1. **Write tests**: All new features and bug fixes MUST include corresponding unit tests
  2. **Format code**: Run `make fmt` to automatically fix formatting issues
  3. **Pass linting**: Run `make lint` to verify code passes linting without errors
