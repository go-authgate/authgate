# CLAUDE.md

This file provides guidance to [Claude Code](https://claude.ai/code) when working with code in this repository.

## Project Overview

AuthGate is an OAuth 2.0 authorization server built with Go and Gin. It supports:

- **Device Authorization Grant (RFC 8628)** - For CLI tools, IoT devices, and headless environments
- **Authorization Code Flow (RFC 6749) with PKCE (RFC 7636)** - For web and mobile applications

Enables secure authentication without embedding client secrets.

## Common Commands

```bash
# Build (IMPORTANT: make generate is required before building)
make generate           # Generate templ templates and Swagger docs (REQUIRED before build)
make build              # Build to bin/authgate with version info in LDFLAGS

# Run
./bin/authgate -v       # Show version information
./bin/authgate -h       # Show help
./bin/authgate server   # Start the OAuth server

# Development
make dev                # Hot reload development mode (watches .go, .templ, .env, .css, .js)
make generate           # Compile .templ templates to Go code (REQUIRED)
make swagger            # Generate OpenAPI/Swagger documentation

# Test & Lint
make test               # Run tests with coverage report (outputs coverage.txt)
make coverage           # View test coverage in browser
make lint               # Run golangci-lint (auto-installs if missing)
make fmt                # Format code with golangci-lint fmt

# Cross-compile (outputs to release/<os>/<arch>/)
make build_linux_amd64  # CGO_ENABLED=0 for static binary
make build_linux_arm64  # CGO_ENABLED=0 for static binary

# Clean
make clean              # Remove bin/, release/, coverage.txt, generated templ files

# Docker
docker build -f docker/Dockerfile -t authgate .
```

## Architecture

### Device Authorization Flow (RFC 8628)

1. CLI calls `POST /oauth/device/code` → receives device_code + user_code + verification_uri
2. User visits `/device` in browser, must login first if not authenticated
3. User submits user_code via `POST /device/verify` → device code marked as authorized
4. CLI polls `POST /oauth/token` with device_code every 5s → receives access_token + refresh_token
5. When access_token expires, CLI uses `grant_type=refresh_token` to get new token

### Authorization Code Flow (RFC 6749)

In addition to Device Code Flow, AuthGate supports Authorization Code Flow with PKCE for web and mobile applications:

1. App redirects user to `GET /oauth/authorize` with client_id, redirect_uri, state, code_challenge (PKCE)
2. User logs in (if needed) and sees consent screen at `/oauth/authorize`
3. User approves → `POST /oauth/authorize` → redirects to redirect_uri with authorization code
4. App exchanges code for tokens via `POST /oauth/token` (with code_verifier for PKCE, or client_secret for confidential clients)

**User Consent Management**

- Users can review granted apps at `/account/authorizations`
- Each authorization grants specific scopes to one app
- Users can revoke per-app access (revokes all associated tokens)
- Admins can force re-authentication for all users of a client via `/admin/clients/:id/revoke-all`

**Client Types**

- **Confidential clients**: Web apps with server-side backends that can securely store client_secret
- **Public clients**: SPAs and mobile apps that use PKCE instead of client_secret

### Technology Stack

- **Web Framework**: [Gin](https://gin-gonic.com/) - Fast HTTP router
- **Templates**: [templ](https://templ.guide/) - Type-safe Go templates (requires `make generate` before build)
- **ORM**: [GORM](https://gorm.io/) - Database abstraction
- **Database**: SQLite (default) / PostgreSQL
- **Sessions**: Encrypted cookies with [gin-contrib/sessions](https://github.com/gin-contrib/sessions)
- **JWT**: [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
- **API Documentation**: Swagger/OpenAPI via [swaggo/swag](https://github.com/swaggo/swag)
- **Hot Reload**: [air](https://github.com/air-verse/air) for development (`make dev`)

### Project Structure (Layers)

- `main.go` - Wires up store → auth providers → token providers → services → handlers
- `internal/config/` - Environment configuration management
- `internal/store/` - GORM-based data access layer (SQLite/PostgreSQL), uses map-based driver factory
- `internal/auth/` - Authentication providers (local, HTTP API, OAuth providers)
- `internal/token/` - Token providers (local JWT, HTTP API)
- `internal/services/` - Business logic layer (user, device, authorization, token, client, audit services)
- `internal/handlers/` - HTTP request handlers for all endpoints
- `internal/models/` - GORM database models (User, OAuthApplication, UserAuthorization, DeviceCode, AuthorizationCode, AccessToken, OAuthConnection, AuditLog)
- `internal/middleware/` - Gin middleware (auth, CSRF, rate limiting, metrics auth)
- `internal/metrics/` - Prometheus metrics collection and caching (supports memory, Redis, Redis-aside)
- `internal/cache/` - Cache implementations (memory, Redis, Redis-aside)
- `internal/client/` - HTTP client with exponential backoff retry
- `internal/templates/` - templ templates (`_.templ` → `_templ.go` via `make generate`)
- `internal/util/` - Utility functions (crypto, context helpers)
- `internal/version/` - Version information injected at build time

**Key Model Details:**

- `OAuthApplication` - Supports both Device Flow and Auth Code Flow with per-client toggles (`EnableDeviceFlow`, `EnableAuthCodeFlow`)
- `OAuthApplication.ClientType` - "confidential" (with secret) or "public" (PKCE only)
- `UserAuthorization` - Per-app consent grants (one record per user+app pair)
- `AccessToken` - Unified storage for both access and refresh tokens (distinguished by `token_category` field)

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
- Event types: AUTHENTICATION*\*, DEVICE_CODE*\_, TOKEN\_\_, CLIENT\_\*, RATE_LIMIT_EXCEEDED
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

**Prometheus Metrics**

- Comprehensive metrics for OAuth flows, authentication, tokens, sessions, HTTP requests, and database queries
- Gauge metrics (active tokens, device codes, sessions) updated at configurable intervals (default: every 5 minutes)
- Multi-replica consideration: Gauge updates query global database counts. In multi-instance deployments:
  - **Recommended**: Enable `METRICS_GAUGE_UPDATE_ENABLED` on only one instance to avoid duplicate values
  - **Alternative**: Enable on all instances, use `max()` or `avg()` aggregation in PromQL (not `sum()`)
- Counters and histograms are safe in multi-replica setups (each instance tracks its own activity)
- Metrics cache support to reduce database load:
  - **Memory cache** (default): Single-instance deployments, zero external dependencies
  - **Redis cache**: Multi-instance deployments (2-5 pods), shared cache across instances using rueidis
  - **Redis-aside cache**: High-load deployments (5+ pods), uses rueidisaside for client-side caching with RESP3 automatic invalidation
- Cache TTL matches update interval to ensure consistency and reduce database queries by 90%+ in multi-instance setups
- Implementation uses rueidisaside library correctly for cache-aside pattern with client-side caching support
- **Memory considerations for redis-aside**: Client-side cache size is configurable via `METRICS_CACHE_SIZE_PER_CONN` (default: 32MB). Total memory usage is `cache_size * number_of_connections`. Rueidis typically maintains ~10 connections (based on GOMAXPROCS), so default usage is ~320MB. Adjust this value based on your deployment's memory constraints and cache hit requirements.

### Key Implementation Details

- Device codes expire after 30min (configurable via `DeviceCodeExpiration`)
- User codes: 8-char uppercase alphanumeric, normalized (uppercase + dashes removed)
- JWTs signed with HMAC-SHA256, expire after 1 hour
- Sessions: encrypted cookies (gin-contrib/sessions), configurable expiry (default: 1 hour), with idle timeout (default: 30 minutes) and fingerprinting (User-Agent validation)
- Polling interval: 5 seconds
- Templates and static files embedded via `//go:embed`
- Error handling: Services return typed errors, handlers convert to RFC 8628 OAuth responses

### Key Endpoints

**OAuth 2.0 Flows**

- `POST /oauth/device/code` - Request device code (Device Flow)
- `GET /oauth/authorize` - Authorization consent page (Auth Code Flow)
- `POST /oauth/authorize` - Submit consent decision (Auth Code Flow)
- `POST /oauth/token` - Token exchange endpoint
  - `grant_type=urn:ietf:params:oauth:grant-type:device_code` - Exchange device_code for tokens
  - `grant_type=authorization_code` - Exchange authorization code for tokens
  - `grant_type=refresh_token` - Refresh access token
- `GET /oauth/tokeninfo` - Verify JWT validity
- `POST /oauth/revoke` - Revoke tokens (RFC 7009)

**User Device & App Management**

- `GET /device` - Device code entry page (protected, requires login)
- `POST /device/verify` - Submit device code to authorize (protected)
- `GET /account/sessions` - Manage active token sessions
- `GET /account/authorizations` - Manage per-app consent grants
- `POST /account/authorizations/:uuid/revoke` - Revoke specific app authorization

**Authentication**

- `GET /login` - Login page
- `POST /login` - Submit credentials
- `GET /logout` - Clear session
- `GET /oauth/:provider` - Initiate OAuth login (GitHub, Gitea, Microsoft)
- `GET /oauth/:provider/callback` - OAuth callback handler

**Admin**

- `GET /admin/clients` - List OAuth applications
- `GET /admin/clients/new` - Create new OAuth client
- `POST /admin/clients` - Save new OAuth client
- `GET /admin/clients/:id/edit` - Edit OAuth client
- `POST /admin/clients/:id/update` - Update OAuth client
- `GET /admin/clients/:id/authorizations` - View all authorized users for a client
- `POST /admin/clients/:id/revoke-all` - Force re-auth for all users of a client
- `GET /admin/audit` - View audit logs with filtering (admin only)
- `GET /admin/audit/export` - Export audit logs as CSV (admin only)

**System**

- `GET /health` - Health check with database connection test
- `GET /metrics` - Prometheus metrics (optional Bearer token auth)
- `GET /api/swagger/*` - Swagger/OpenAPI documentation

## Configuration

Key configuration categories (see `.env.example` and `docs/CONFIGURATION.md` for complete details):

**Core Settings**

- `SERVER_ADDR`, `BASE_URL` - Server address and public URL
- `JWT_SECRET`, `SESSION_SECRET` - Must be changed in production (use `openssl rand -hex 32`)
- `DATABASE_DRIVER` (sqlite/postgres), `DATABASE_DSN` - Database configuration

**Authentication & Authorization**

- `AUTH_MODE` (local/http_api) - Authentication backend
- `TOKEN_PROVIDER_MODE` (local/http_api) - Token generation backend
- `ENABLE_REFRESH_TOKENS`, `ENABLE_TOKEN_ROTATION` - Refresh token modes (fixed vs rotation)

**Security Features**

- `ENABLE_RATE_LIMIT`, `RATE_LIMIT_STORE` (memory/redis) - Rate limiting
- `ENABLE_AUDIT_LOGGING` - Comprehensive audit trails
- `SESSION_FINGERPRINT` - Session security (User-Agent validation)

**OAuth Providers**

- `GITHUB_OAUTH_ENABLED`, `GITEA_OAUTH_ENABLED`, `MICROSOFT_OAUTH_ENABLED` - Third-party OAuth login

**Observability**

- `METRICS_ENABLED` - Prometheus metrics endpoint
- `METRICS_CACHE_TYPE` (memory/redis/redis-aside) - Metrics caching for multi-instance deployments
- `METRICS_GAUGE_UPDATE_ENABLED` - Set to false on all but one replica in multi-instance setups

## Default Test Data

Seeded automatically on first run (store/sqlite.go:seedData):

- User: `admin` / `<random_password>` (16-character random password, logged at startup, bcrypt hashed)
- Client: `AuthGate CLI` (client_id is auto-generated UUID, logged at startup)

## Example CLI Clients

[github.com/go-authgate/device-cli](https://github.com/go-authgate/device-cli) contains a demo CLI that demonstrates the device flow:

```bash
git clone https://github.com/go-authgate/device-cli
cd device-cli
cp .env.example .env      # Add CLIENT_ID from server logs
go run main.go
```

[github.com/go-authgate/oauth-cli](https://github.com/go-authgate/oauth-cli) demonstrates Authorization Code Flow + PKCE.

For a hybrid CLI that auto-detects the environment (browser on local, Device Code over SSH), see [github.com/go-authgate/cli](https://github.com/go-authgate/cli).

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
- GORM models use `gorm.Model` for CreatedAt/UpdatedAt/DeletedAt (except custom timestamp models)
- Handlers accept both form-encoded and JSON request bodies where applicable
- All static assets and templates are embedded via `//go:embed` for single-binary deployment
- **Templates**: Use [templ](https://templ.guide/) for type-safe HTML templates
  - `.templ` files are compiled to `_templ.go` files via `make generate`
  - Never edit `_templ.go` files directly - always edit the source `.templ` files
  - Run `make generate` after modifying any `.templ` file
- **Interfaces**: Follow Go best practices - define interfaces where abstraction adds value
  - **Currently have interfaces**: `Cache`, `MetricsCollector` (swappable implementations)
  - **Should consider adding interfaces** for pluggable components to improve extensibility and testability:
    - `AuthProvider` - Already has 3 implementations (local, http_api, OAuth); interface would enable third-party auth backends
    - `TokenProvider` - Already has 2 implementations (local JWT, http_api); interface would enable custom token formats (e.g., RS256, ES256)
    - `Store` - Supports SQLite/PostgreSQL; interface would enable MySQL, MongoDB, or custom storage backends
  - **Don't need interfaces**: Services (UserService, DeviceService, etc.) - these are core business logic with single implementations
  - Use direct struct dependency injection for simplicity where multiple implementations are unlikely
- **Audit Logging**: Services that modify data should log audit events
  - Use `auditService.Log()` for normal events (async, non-blocking)
  - Use `auditService.LogSync()` for critical security events (synchronous)
  - Sensitive data is automatically masked by AuditService (passwords, tokens, secrets)
- **API Documentation**: Use Swagger annotations in handlers for OpenAPI generation
  - Annotations use swaggo format: `// @Summary`, `// @Description`, `// @Tags`, etc.
  - Run `make swagger` to regenerate documentation
- **IMPORTANT**: Before committing changes:
  1. **Generate code**: Run `make generate` to compile templates and update Swagger docs
  2. **Write tests**: All new features and bug fixes MUST include corresponding unit tests
  3. **Format code**: Run `make fmt` to automatically fix formatting issues
  4. **Pass linting**: Run `make lint` to verify code passes linting without errors
