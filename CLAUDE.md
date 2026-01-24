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

### Device Authorization Flow (with Refresh Tokens)

1. CLI calls `POST /oauth/device/code` with client_id → receives device_code + user_code + verification_uri
2. User visits verification_uri (`/device`) in browser, must login first if not authenticated
3. User submits user_code via `POST /device/verify` → device code marked as authorized
4. CLI polls `POST /oauth/token` with device_code every 5s → receives access_token + refresh_token when authorized
5. CLI uses access_token for API calls (expires in 1 hour)
6. When access_token expires, CLI calls `POST /oauth/token` with `grant_type=refresh_token` → receives new access_token (fixed mode) or new access_token + refresh_token (rotation mode)

### Layers (dependency injection pattern)

- `main.go` - Wires up store → auth providers → token providers → services → handlers, configures Gin router with session middleware
- `config/` - Loads .env via godotenv, provides Config struct with defaults
- `store/` - GORM-based data access layer, supports SQLite and PostgreSQL via driver factory pattern
  - `driver.go` - Database driver factory using map-based pattern (no if-else)
  - `sqlite.go` - Store implementation and database operations (driver-agnostic)
- `auth/` - Authentication providers (LocalAuthProvider, HTTPAPIAuthProvider) with pluggable design
- `token/` - Token providers (LocalTokenProvider, HTTPTokenProvider) with pluggable design
  - `types.go` - Shared data structures (TokenResult, TokenValidationResult)
  - `errors.go` - Provider-level error definitions
  - `local.go` - Local JWT provider (HMAC-SHA256)
  - `http_api.go` - External HTTP API token provider
- `services/` - Business logic (UserService, DeviceService, TokenService), depends on Store, Auth providers, and Token providers
- `handlers/` - HTTP handlers (AuthHandler, DeviceHandler, TokenHandler), depends on Services
- `models/` - GORM models (User, OAuthClient, DeviceCode, AccessToken)
- `middleware/` - Gin middleware (auth.go: RequireAuth checks session for user_id)

### Authentication Architecture

- **Pluggable Providers**: Supports local (database) and external HTTP API authentication
- **Hybrid Mode**: Each user authenticates based on their `auth_source` field
- **Auth Mode**: Configured via `AUTH_MODE` env var (`local` or `http_api`), defaults to `local`
- **User Sync**: External auth automatically creates/updates users in local database
- **No Interfaces**: Direct struct dependency injection (project convention)
- **Authentication Flow**:
  1. UserService looks up user by username
  2. If user exists: route to provider based on user's `auth_source` field
     - `auth_source=local`: LocalAuthProvider (bcrypt against database)
     - `auth_source=http_api`: HTTPAPIAuthProvider (call external API)
  3. If user doesn't exist and `AUTH_MODE=http_api`: try external auth and create user
  4. Default admin user always uses local authentication (failsafe)
- **User Fields**: ExternalID, AuthSource, Email, FullName added for external auth support
- **Key Benefit**: Admin can always login locally even if external service is down

### Token Provider Architecture

- **Pluggable Providers**: Supports local JWT generation/validation and external HTTP API token services
- **Global Mode**: Configured via `TOKEN_PROVIDER_MODE` env var (`local` or `http_api`), defaults to `local`
- **Local Storage**: Token records always stored in local database for management (revocation, listing, auditing)
- **No Interfaces**: Direct struct dependency injection (project convention, following auth provider pattern)
- **Token Generation Flow**:
  1. TokenService receives token generation request (from ExchangeDeviceCode)
  2. Selects provider based on `TOKEN_PROVIDER_MODE` configuration
     - `local`: LocalTokenProvider generates JWT with HMAC-SHA256 using `JWT_SECRET`
     - `http_api`: HTTPTokenProvider calls external API to generate JWT
  3. Saves token record to local database (regardless of provider)
  4. Returns AccessToken to client
- **Token Validation Flow**:
  1. TokenService receives validation request (from TokenInfo endpoint)
  2. Selects provider based on `TOKEN_PROVIDER_MODE` configuration
     - `local`: LocalTokenProvider validates JWT signature with `JWT_SECRET`
     - `http_api`: HTTPTokenProvider calls external API to validate JWT
  3. Returns TokenValidationResult with claims
- **Provider Types**:
  - `LocalTokenProvider`: Uses golang-jwt/jwt library for HMAC-SHA256 signing
  - `HTTPTokenProvider`: Delegates to external HTTP API, supports custom signing algorithms (RS256, ES256, etc.)
- **API Contract**: HTTPTokenProvider expects `/generate` and `/validate` endpoints with specific JSON format
- **Key Benefit**: Centralized token services, advanced key management, compliance requirements while maintaining local token management

### Refresh Token Architecture

AuthGate supports refresh tokens following RFC 6749 with configurable rotation modes for different security requirements.

- **Key Features**:
  - **Dual Modes**: Fixed (reusable) vs Rotation (one-time use) refresh tokens
  - **Unified Storage**: Both access and refresh tokens stored in `AccessToken` table with `token_category` field
  - **Token Family Tracking**: `parent_token_id` links tokens for audit trails and revocation
  - **Status Management**: Tokens can be `active`, `disabled`, or `revoked`
  - **Configurable Expiration**: `REFRESH_TOKEN_EXPIRATION` env var (default: 720h = 30 days)
  - **Provider Support**: Both LocalTokenProvider and HTTPTokenProvider support refresh operations

- **Fixed Mode (Default - Multi-Device Friendly)**:
  1. Device code exchange returns `access_token` + `refresh_token`
  2. When access token expires, client POSTs to `/oauth/token` with `grant_type=refresh_token`
  3. Server returns new `access_token` only (refresh token remains unchanged and reusable)
  4. Process repeats until refresh token expires or is manually disabled/revoked
  5. Each device/application gets its own refresh token that doesn't affect others
  6. Users can manage all tokens (disable/enable/revoke) via backend UI
  7. LastUsedAt field tracks activity for identifying inactive sessions

- **Rotation Mode (Optional - High Security)**:
  1. Same as fixed mode, but step 3 returns both new `access_token` + new `refresh_token`
  2. Old refresh token is automatically revoked (status set to 'revoked') after each use
  3. Prevents token replay attacks
  4. Requires clients to update stored refresh token after each use
  5. Enable via `ENABLE_TOKEN_ROTATION=true`

- **Token Management**:
  - **Status Field**: `active` (usable) / `disabled` (temporarily blocked, can re-enable) / `revoked` (permanently blocked)
  - **Independent Revocation**: Revoking refresh token doesn't affect existing access tokens
  - **Family Tracking**: ParentTokenID enables audit trails and selective revocation
  - **Scope Validation**: Refresh requests cannot escalate privileges beyond original grant

- **Environment Variables**:
  - `REFRESH_TOKEN_EXPIRATION=720h` - Refresh token lifetime (default: 30 days)
  - `ENABLE_REFRESH_TOKENS=true` - Feature flag (default: enabled)
  - `ENABLE_TOKEN_ROTATION=false` - Enable rotation mode (default: disabled, uses fixed mode)

- **Grant Type Support**:
  - `urn:ietf:params:oauth:grant-type:device_code` - Device authorization flow (returns access + refresh)
  - `refresh_token` - RFC 6749 refresh token grant (returns new tokens)

- **Security Considerations**:
  - Refresh tokens validated by type claim (`"type": "refresh"` in JWT)
  - Refresh tokens cannot be used as access tokens (separate validation logic)
  - Client ID verification prevents cross-client token usage
  - Token family tracking enables detection of suspicious patterns
  - Optional rotation mode for high-security scenarios

### Key Implementation Details

- Device codes expire after 30min (configurable via Config.DeviceCodeExpiration)
- User codes are 8-char uppercase alphanumeric (generated by generateUserCode in services/device.go)
- User codes normalized: uppercase + dashes removed before lookup
- JWTs signed with HMAC-SHA256, expire after 1 hour (Config.JWTExpiration)
- Sessions stored in encrypted cookies (gin-contrib/sessions), 7-day expiry
- Polling interval is 5 seconds (Config.PollingInterval)
- Templates and static files embedded via go:embed in main.go

### Key Endpoints

- `GET /health` - Health check with database connection test
- `POST /oauth/device/code` - CLI requests device+user codes (accepts form or JSON)
- `POST /oauth/token` - Token endpoint supporting multiple grant types:
  - `grant_type=urn:ietf:params:oauth:grant-type:device_code` - Device authorization flow (returns access + refresh tokens)
  - `grant_type=refresh_token` - Refresh token grant (RFC 6749) - returns new access token (fixed mode) or new access + refresh tokens (rotation mode)
- `GET /oauth/tokeninfo` - Verify JWT validity
- `POST /oauth/revoke` - Revoke tokens (RFC 7009)
- `GET /device` - User authorization page (protected, requires login)
- `POST /device/verify` - User submits code to authorize device (protected)
- `GET|POST /login` - User authentication
- `GET /logout` - Clear session

### Error Handling

Services return typed errors (ErrInvalidClient, ErrDeviceCodeNotFound, etc.), handlers convert to RFC 8628 OAuth error responses.

## Environment Variables

| Variable                       | Default                 | Description                                                              |
| ------------------------------ | ----------------------- | ------------------------------------------------------------------------ |
| SERVER_ADDR                    | :8080                   | Listen address                                                           |
| BASE_URL                       | `http://localhost:8080` | Public URL for verification_uri                                          |
| JWT_SECRET                     | (default)               | JWT signing key (used when TOKEN_PROVIDER_MODE=local)                    |
| SESSION_SECRET                 | (default)               | Cookie encryption key                                                    |
| DATABASE_DRIVER                | sqlite                  | Database driver ("sqlite" or "postgres")                                 |
| DATABASE_DSN                   | oauth.db                | Connection string (path for SQLite, DSN for PostgreSQL)                  |
| **AUTH_MODE**                  | local                   | Authentication mode: `local` or `http_api`                               |
| HTTP_API_URL                   | (none)                  | External auth API endpoint (required when AUTH_MODE=http_api)            |
| HTTP_API_TIMEOUT               | 10s                     | HTTP API request timeout                                                 |
| HTTP_API_INSECURE_SKIP_VERIFY  | false                   | Skip TLS verification (dev/testing only)                                 |
| HTTP_API_AUTH_MODE             | none                    | Service-to-service auth mode: `none`, `simple`, or `hmac`                |
| HTTP_API_AUTH_SECRET           | (none)                  | Shared secret for service-to-service authentication                      |
| HTTP_API_AUTH_HEADER           | X-API-Secret            | Custom header name for simple auth mode                                  |
| **TOKEN_PROVIDER_MODE**        | local                   | Token provider mode: `local` or `http_api`                               |
| TOKEN_API_URL                  | (none)                  | External token API endpoint (required when TOKEN_PROVIDER_MODE=http_api) |
| TOKEN_API_TIMEOUT              | 10s                     | Token API request timeout                                                |
| TOKEN_API_INSECURE_SKIP_VERIFY | false                   | Skip TLS verification for token API (dev/testing only)                   |
| TOKEN_API_AUTH_MODE            | none                    | Service-to-service auth mode: `none`, `simple`, or `hmac`                |
| TOKEN_API_AUTH_SECRET          | (none)                  | Shared secret for service-to-service authentication                      |
| TOKEN_API_AUTH_HEADER          | X-API-Secret            | Custom header name for simple auth mode                                  |
| **REFRESH_TOKEN_EXPIRATION**   | 720h                    | Refresh token lifetime (default: 30 days)                                |
| **ENABLE_REFRESH_TOKENS**      | true                    | Feature flag to enable/disable refresh tokens                            |
| **ENABLE_TOKEN_ROTATION**      | false                   | Enable rotation mode (default: false, uses fixed mode)                   |

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

## External Authentication Configuration

### HTTP API Authentication

To use external HTTP API for authentication, configure these environment variables:

```bash
AUTH_MODE=http_api
HTTP_API_URL=https://your-auth-api.com/verify
HTTP_API_TIMEOUT=10s
HTTP_API_INSECURE_SKIP_VERIFY=false
```

#### Authentication API Contract

Request (POST to HTTP_API_URL):

```json
{
  "username": "john",
  "password": "secret123"
}
```

Response:

```json
{
  "success": true,
  "user_id": "external-user-id",
  "email": "john@example.com",
  "full_name": "John Doe"
}
```

#### Authentication Response Requirements

- `success` (required): Boolean indicating authentication result
- `user_id` (required when success=true): Non-empty string uniquely identifying the user in external system
- `email` (optional): User's email address
- `full_name` (optional): User's display name
- `message` (optional): Error message when success=false or HTTP status is non-2xx

#### Authentication Behavior

- First login auto-creates user in local database with `auth_source="http_api"`
- Subsequent logins update user info (email, full_name)
- Users get default "user" role (admins must be promoted manually)
- External users stored with `auth_source="http_api"` and `external_id` set
- Each user authenticates based on their own `auth_source` field (hybrid mode)
- Default admin user (`auth_source="local"`) can always login even if external API is down
- Missing or empty `user_id` when `success=true` will cause authentication to fail
- **Username conflicts**: If external username matches existing user, login fails with error
  - User sees: "Username conflict with existing user. Please contact administrator."
  - Administrator must either: (1) rename existing user, (2) update external API username, or (3) manually merge accounts

### Local Authentication (Default)

No additional configuration needed. Users authenticate against local SQLite database:

```bash
AUTH_MODE=local  # or omit AUTH_MODE entirely
```

### Hybrid Mode Advantages

The system supports **per-user authentication routing** based on the `auth_source` field:

- **Failsafe Admin Access**: Default admin user always uses local auth, providing emergency access
- **Mixed User Base**: Can have both local and external users in the same system
- **Zero Downtime Migration**: Gradually migrate users from local to external auth
- **Service Independence**: External service outage doesn't lock out local users

#### Example Scenario

1. Server starts with `AUTH_MODE=http_api`
2. Default admin user created with `auth_source=local` (can always login)
3. External users authenticate via HTTP API, created with `auth_source=http_api`
4. Each user authenticates via their designated provider
5. If external API fails, admin can still login to manage the system

## External Token Provider Configuration

### HTTP API Token Provider

To use external HTTP API for token generation and validation, configure these environment variables:

```bash
TOKEN_PROVIDER_MODE=http_api
TOKEN_API_URL=https://token-service.example.com/api
TOKEN_API_TIMEOUT=10s
TOKEN_API_INSECURE_SKIP_VERIFY=false
```

#### Token API Contract

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

Response (Success):

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

Response (Error):

```json
{
  "success": false,
  "message": "Invalid user_id or client_id"
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
  "message": "Token expired or signature invalid"
}
```

#### Token Response Requirements

Generation Response:

- `success` (required): Boolean indicating generation result
- `access_token` (required when success=true): Non-empty JWT string
- `token_type` (optional): Token type, defaults to "Bearer"
- `expires_in` (optional): Expiration duration in seconds
- `claims` (optional): Additional JWT claims
- `message` (optional): Error message when success=false

Validation Response:

- `valid` (required): Boolean indicating validation result
- `user_id` (required when valid=true): User identifier from token
- `client_id` (required when valid=true): Client identifier from token
- `scopes` (required when valid=true): Granted scopes
- `expires_at` (required when valid=true): Unix timestamp of expiration
- `claims` (optional): Additional JWT claims
- `message` (optional): Error message when valid=false

#### Token Provider Behavior

- Token generation/validation delegated to external service
- Token records still saved to local database for management
- Supports custom signing algorithms (RS256, ES256, etc.)
- Local database tracks: token ID, token string, user_id, client_id, scopes, expiration
- Revocation handled locally (external service doesn't need revocation endpoint)
- Token listing handled locally (external service doesn't need listing endpoint)

### Local Token Provider (Default)

No additional configuration needed. Tokens generated/validated using local JWT secret:

```bash
TOKEN_PROVIDER_MODE=local  # or omit TOKEN_PROVIDER_MODE entirely
JWT_SECRET=your-256-bit-secret-change-in-production
```

### Token Provider Benefits

#### Local Mode

- Simple setup, no external dependencies
- Fast token operations
- Self-contained deployment

#### HTTP API Mode

- Centralized token services across multiple applications
- Advanced key management and rotation
- Custom signing algorithms (RS256, ES256)
- Compliance requirements for token generation
- Integration with existing IAM/PKI systems

#### Why Local Storage is Retained

- Revocation: Users can revoke tokens via `/account/sessions` or `/oauth/revoke`
- Management: Users can list active sessions
- Auditing: Track when and for which clients tokens were issued
- Client Association: Link tokens to OAuth clients for display in UI

## Service-to-Service Authentication

When using external HTTP APIs for authentication (`AUTH_MODE=http_api`) or token operations (`TOKEN_PROVIDER_MODE=http_api`), you can secure the communication between AuthGate and these services using service-to-service authentication.

### Authentication Modes

#### 1. None Mode (Default)

No authentication headers are added. Use only in trusted internal networks.

```bash
HTTP_API_AUTH_MODE=none
# or omit HTTP_API_AUTH_MODE entirely
```

#### 2. Simple Mode (Shared Secret)

Adds a simple API secret header to each request. Quick to set up, suitable for internal services.

```bash
# For HTTP API Authentication
HTTP_API_AUTH_MODE=simple
HTTP_API_AUTH_SECRET=your-shared-secret-key
HTTP_API_AUTH_HEADER=X-API-Secret  # Optional, defaults to X-API-Secret

# For Token API
TOKEN_API_AUTH_MODE=simple
TOKEN_API_AUTH_SECRET=your-shared-secret-key
TOKEN_API_AUTH_HEADER=X-API-Secret  # Optional
```

##### Simple Mode: Request Headers

```txt
X-API-Secret: your-shared-secret-key
```

##### Simple Mode: Server-side Validation

```go
secret := r.Header.Get("X-API-Secret")
if secret != expectedSecret {
    return http.StatusUnauthorized
}
```

#### 3. HMAC Mode (Signature-based)

Calculates HMAC-SHA256 signature for each request. Provides protection against tampering and replay attacks. Recommended for production.

```bash
# For HTTP API Authentication
HTTP_API_AUTH_MODE=hmac
HTTP_API_AUTH_SECRET=your-shared-secret-key

# For Token API
TOKEN_API_AUTH_MODE=hmac
TOKEN_API_AUTH_SECRET=your-shared-secret-key
```

##### HMAC Mode: Request Headers

```txt
X-Signature: <hmac-sha256-hex>
X-Timestamp: <unix-timestamp>
X-Nonce: <random-uuid>
Content-Type: application/json
```

##### Signature Calculation

```txt
message = timestamp + method + path + body
signature = HMAC-SHA256(secret, message)
```

##### Example in Go

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

message := fmt.Sprintf("%d%s%s%s", timestamp, "POST", "/api/auth", requestBody)
h := hmac.New(sha256.New, []byte(secret))
h.Write([]byte(message))
signature := hex.EncodeToString(h.Sum(nil))
```

##### HMAC Mode: Server-side Validation

```go
import httpclient "github.com/appleboy/go-httpclient"

authConfig := &httpclient.AuthConfig{
    Mode:   httpclient.AuthModeHMAC,
    Secret: "your-shared-secret-key",
}

// Verify signature (checks timestamp age and signature validity)
err := authConfig.VerifyHMACSignature(req, 5*time.Minute)
if err != nil {
    return http.StatusUnauthorized
}
```

##### Security Features

- **Timestamp validation**: Requests older than 5 minutes are rejected (prevents replay attacks)
- **Signature verification**: Ensures request hasn't been tampered with
- **Nonce**: Adds uniqueness to each request (can be logged for additional replay protection)

### Configuration Examples

#### Example 1: Simple mode for internal network

```bash
# .env
AUTH_MODE=http_api
HTTP_API_URL=http://internal-auth-service:8080/verify
HTTP_API_AUTH_MODE=simple
HTTP_API_AUTH_SECRET=internal-shared-secret-abc123
```

#### Example 2: HMAC mode for production

```bash
# .env
AUTH_MODE=http_api
HTTP_API_URL=https://auth-api.example.com/verify
HTTP_API_AUTH_MODE=hmac
HTTP_API_AUTH_SECRET=production-secret-change-this

TOKEN_PROVIDER_MODE=http_api
TOKEN_API_URL=https://token-api.example.com
TOKEN_API_AUTH_MODE=hmac
TOKEN_API_AUTH_SECRET=token-service-secret-change-this
```

#### Example 3: Custom header name

```bash
# .env
HTTP_API_AUTH_MODE=simple
HTTP_API_AUTH_SECRET=my-secret
HTTP_API_AUTH_HEADER=X-Internal-Token  # Custom header name
```

### Implementation Notes

- **Per-Service Configuration**: Auth API and Token API have independent authentication settings
- **Backward Compatible**: Defaults to `none` mode, existing deployments continue working
- **Error Handling**: Authentication failures are logged but don't expose secret details
- **Testing**: Set `HTTP_API_INSECURE_SKIP_VERIFY=true` for self-signed certificates (dev only)

### Security Recommendations

1. **Production**: Use HMAC mode with strong secrets (32+ characters)
2. **Development**: Simple mode acceptable for local/internal testing
3. **Secret Rotation**: Coordinate secret changes between AuthGate and external services
4. **HTTPS Required**: Always use HTTPS for external API calls in production
5. **Logging**: External services should log authentication attempts for audit trails

## Coding Conventions

- Use `http.StatusOK`, `http.StatusBadRequest`, etc. instead of numeric status codes
- Services return typed errors, handlers convert to appropriate HTTP responses
- GORM models use `gorm.Model` for CreatedAt/UpdatedAt/DeletedAt
- Handlers accept both form-encoded and JSON request bodies where applicable
- All static assets and templates are embedded via `//go:embed` for single-binary deployment
- Database connection health check available via `store.Health()` method
- **IMPORTANT**: Before committing changes:
  1. **Write tests**: All new features and bug fixes MUST include corresponding unit tests
  2. **Format code**: Run `make fmt` to automatically fix code formatting issues and ensure consistency
  3. **Pass linting**: Run `make lint` to verify all code passes linting without errors
