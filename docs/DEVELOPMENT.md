# Development Guide

This guide helps developers build, test, and extend AuthGate.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Build Commands](#build-commands)
- [Testing](#testing)
- [Database Schema](#database-schema)
- [Extending the Server](#extending-the-server)
- [Code Style and Conventions](#code-style-and-conventions)

---

## Prerequisites

- **Go 1.24 or higher**
- **Make** (optional, but recommended for convenience commands)
- **Git** (for version control)
- **golangci-lint** (automatically installed by `make lint`)

---

## Getting Started

### Clone Repository

```bash
# Clone the repository
git clone <repository-url>
cd authgate
```

### Install Dependencies

```bash
# Download Go modules
go mod download

# Verify dependencies
go mod verify
```

### Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

Minimum `.env` for development:

```bash
SERVER_ADDR=:8080
BASE_URL=http://localhost:8080
JWT_SECRET=dev-secret-change-in-production
SESSION_SECRET=dev-session-secret
DATABASE_DSN=oauth.db
```

### Run Development Server

```bash
# Run directly with Go
go run . server

# Or build and run
make build
./bin/authgate server

# Enable debug mode
GIN_MODE=debug ./bin/authgate server
```

The server will start on `http://localhost:8080`.

---

## Build Commands

### Basic Build

```bash
# Build binary with version info (outputs to bin/authgate)
make build

# Build directly with Go (no version info)
go build -o bin/authgate .
```

### Install to $GOPATH/bin

```bash
# Install binary to $GOPATH/bin
make install

# Now you can run from anywhere
authgate server
```

### Cross-Compilation

```bash
# Build static binary for Linux (amd64)
make build_linux_amd64
# Output: release/linux/amd64/authgate

# Build static binary for Linux (arm64)
make build_linux_arm64
# Output: release/linux/arm64/authgate
```

### Build Details

- Version information is automatically embedded using git tags/commits
- LDFLAGS includes: Version, BuildTime, GitCommit, GoVersion, BuildOS, BuildArch
- Cross-compiled binaries are statically linked (CGO_ENABLED=0)
- Output locations:
  - `bin/` - Local builds
  - `release/<os>/<arch>/` - Cross-compilation

### View Version Information

```bash
# Show version
./bin/authgate -v
./bin/authgate --version

# Output example:
# Version: v1.0.0
# Build Time: 2026-02-08T10:00:00Z
# Git Commit: abc1234
# Go Version: go1.24.0
# OS/Arch: linux/amd64
```

---

## Testing

### Run Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
make test

# View coverage report
go tool cover -html=coverage.txt
```

### Run Specific Tests

```bash
# Test a specific package
go test ./services/...

# Test a specific function
go test ./services -run TestDeviceService_GenerateDeviceCode

# Verbose output
go test -v ./...
```

### Test Coverage Requirements

- Aim for >80% code coverage
- All new features must include tests
- All bug fixes must include regression tests

---

## Database Schema

The application automatically creates these tables on startup:

### Users Table

```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    full_name TEXT,
    role TEXT DEFAULT 'user',
    auth_source TEXT DEFAULT 'local',
    external_id TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME
);
```

### OAuth Clients Table

```sql
CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client_id TEXT UNIQUE NOT NULL,
    redirect_uris TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME
);
```

### Device Codes Table

```sql
CREATE TABLE device_codes (
    id TEXT PRIMARY KEY,
    device_code TEXT UNIQUE NOT NULL,
    user_code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT,
    scopes TEXT,
    expires_at DATETIME NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Access Tokens Table

```sql
CREATE TABLE access_tokens (
    id TEXT PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT,
    expires_at DATETIME NOT NULL,
    status TEXT DEFAULT 'active',
    token_category TEXT DEFAULT 'access',
    parent_token_id TEXT,
    last_used_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id),
    FOREIGN KEY (parent_token_id) REFERENCES access_tokens(id)
);
```

### OAuth Connections Table

```sql
CREATE TABLE oauth_connections (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expiry DATETIME,
    profile_data TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE (provider, provider_user_id)
);
```

### Audit Logs Table

```sql
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    event_time DATETIME NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor_user_id TEXT,
    actor_username TEXT,
    actor_ip TEXT,
    resource_type TEXT,
    resource_id TEXT,
    resource_name TEXT,
    action TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    message TEXT,
    metadata TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME
);

CREATE INDEX idx_audit_logs_event_time ON audit_logs(event_time);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_actor_user_id ON audit_logs(actor_user_id);
CREATE INDEX idx_audit_logs_actor_ip ON audit_logs(actor_ip);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity);
CREATE INDEX idx_audit_logs_success ON audit_logs(success);
```

### Database Migrations

GORM AutoMigrate handles schema creation and updates automatically:

```go
db.AutoMigrate(
    &models.User{},
    &models.OAuthClient{},
    &models.DeviceCode{},
    &models.AccessToken{},
    &models.OAuthConnection{},
    &models.AuditLog{},
)
```

---

## Extending the Server

### Add a New OAuth Client

```go
// In store/sqlite.go or via CLI
client := &models.OAuthClient{
    Name:         "My Custom App",
    ClientID:     uuid.New().String(),
    RedirectURIs: "http://localhost:3000/callback",
}
db.Create(client)
```

### Add Custom Scopes

Modify `services/device.go` to validate and store additional scopes:

```go
func (s *DeviceService) ValidateScopes(scopes string) error {
    // Add custom scope validation logic
    validScopes := map[string]bool{
        "read":   true,
        "write":  true,
        "admin":  true,
        // Add your custom scopes here
    }

    requestedScopes := strings.Split(scopes, " ")
    for _, scope := range requestedScopes {
        if !validScopes[scope] {
            return fmt.Errorf("invalid scope: %s", scope)
        }
    }

    return nil
}
```

### Add a New Authentication Provider

1. Create a new provider in `auth/` directory:

```go
// auth/ldap_provider.go
package auth

type LDAPAuthProvider struct {
    // LDAP configuration
}

func (p *LDAPAuthProvider) Authenticate(username, password string) (*AuthResult, error) {
    // LDAP authentication logic
    return &AuthResult{
        Success:  true,
        UserID:   "user-id",
        Email:    "user@example.com",
        FullName: "User Name",
    }, nil
}
```

2. Update `main.go` to wire up the new provider:

```go
// Create LDAP provider
ldapProvider := &auth.LDAPAuthProvider{
    // Configuration
}

// Pass to UserService
userService := services.NewUserService(
    db,
    localProvider,
    httpAPIProvider,
    ldapProvider, // Add here
)
```

### Add a New Endpoint

1. Create handler in `handlers/`:

```go
// handlers/custom.go
func (h *CustomHandler) MyEndpoint(c *gin.Context) {
    // Handler logic
    c.JSON(http.StatusOK, gin.H{
        "message": "Success",
    })
}
```

2. Register route in `main.go`:

```go
// Custom endpoints
customHandler := handlers.NewCustomHandler(customService)
router.GET("/api/custom", customHandler.MyEndpoint)
```

---

## Code Style and Conventions

### General Guidelines

- Use `http.StatusOK`, `http.StatusBadRequest`, etc. instead of numeric codes
- Services return typed errors, handlers convert to appropriate HTTP responses
- GORM models use `gorm.Model` for CreatedAt/UpdatedAt/DeletedAt
- Handlers accept both form-encoded and JSON request bodies where applicable
- All static assets and templates are embedded via `//go:embed`

### Error Handling

```go
// Services return typed errors
var (
    ErrInvalidClient      = errors.New("invalid client")
    ErrDeviceCodeNotFound = errors.New("device code not found")
)

// Handlers convert to RFC 8628 OAuth error responses
if err == services.ErrDeviceCodeNotFound {
    c.JSON(http.StatusBadRequest, gin.H{
        "error": "invalid_grant",
        "error_description": "Device code not found or expired",
    })
    return
}
```

### Dependency Injection

AuthGate uses constructor-based dependency injection (no interfaces):

```go
// Service constructor
func NewUserService(
    db *gorm.DB,
    localAuthProvider *auth.LocalAuthProvider,
    httpAPIAuthProvider *auth.HTTPAPIAuthProvider,
) *UserService {
    return &UserService{
        db:                  db,
        localAuthProvider:   localAuthProvider,
        httpAPIAuthProvider: httpAPIAuthProvider,
    }
}

// Handler constructor
func NewAuthHandler(userService *services.UserService) *AuthHandler {
    return &AuthHandler{
        userService: userService,
    }
}
```

### Linting and Formatting

```bash
# Format code
make fmt

# Run linter
make lint

# Auto-fix issues (where possible)
golangci-lint run --fix
```

### Pre-Commit Checklist

Before committing changes:

1. **Write tests**: All new features and bug fixes MUST include tests
2. **Format code**: Run `make fmt`
3. **Pass linting**: Run `make lint` (must pass without errors)
4. **Test locally**: Run `make test` (coverage should not decrease)
5. **Update documentation**: Update relevant docs if behavior changes

---

## Debugging

### Enable Debug Mode

```bash
# Enable Gin debug logging
GIN_MODE=debug ./bin/authgate server
```

### Database Query Logging

```bash
# Enable GORM debug mode in store/sqlite.go
db.Debug().Where("username = ?", username).First(&user)
```

### Common Development Issues

**Issue: Port already in use**

```bash
# Find process using port 8080
lsof -i :8080

# Kill process
kill -9 <PID>
```

**Issue: Database locked**

```bash
# Ensure only one instance is running
pkill authgate

# Delete lock file if necessary
rm oauth.db-shm oauth.db-wal
```

---

## Clean Up

```bash
# Remove build artifacts
make clean

# Remove database (use with caution!)
rm oauth.db

# Reset everything
make clean
rm oauth.db .env
```

---

**Next Steps:**

- [Architecture Guide](ARCHITECTURE.md) - Understand the system design
- [Configuration Guide](CONFIGURATION.md) - Configure advanced features
- [Testing Guide](#testing) - Write comprehensive tests
