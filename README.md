# AuthGate

> A lightweight OAuth 2.0 Device Authorization Grant server for CLI tools and browserless devices

[![Security Scanning](https://github.com/appleboy/authgate/actions/workflows/security.yml/badge.svg)](https://github.com/appleboy/authgate/actions/workflows/security.yml)
[![Lint and Testing](https://github.com/appleboy/authgate/actions/workflows/testing.yml/badge.svg)](https://github.com/appleboy/authgate/actions/workflows/testing.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Table of Contents

- [AuthGate](#authgate)
  - [Table of Contents](#table-of-contents)
  - [Why AuthGate?](#why-authgate)
    - [The Problem](#the-problem)
    - [Real-World Scenarios](#real-world-scenarios)
    - [The Solution](#the-solution)
  - [Features](#features)
  - [Quick Start](#quick-start)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Run the Server](#run-the-server)
    - [Docker Deployment](#docker-deployment)
      - [Docker Features](#docker-features)
      - [Docker Compose Example](#docker-compose-example)
    - [Test with the Example CLI](#test-with-the-example-cli)
  - [User Interface](#user-interface)
    - [1. Login Page](#1-login-page)
    - [2. Device Authorization Page](#2-device-authorization-page)
    - [3. Authorization Success](#3-authorization-success)
    - [4. Session Management](#4-session-management)
  - [How It Works](#how-it-works)
    - [Device Flow Sequence](#device-flow-sequence)
    - [Key Endpoints](#key-endpoints)
      - [Endpoint Details](#endpoint-details)
        - [Device Flow (CLI)](#device-flow-cli)
        - [User Authorization (Browser)](#user-authorization-browser)
        - [Token Validation](#token-validation)
        - [Token Revocation (RFC 7009)](#token-revocation-rfc-7009)
        - [Session Management (Web UI)](#session-management-web-ui)
  - [Configuration](#configuration)
    - [Environment Variables](#environment-variables)
      - [Generate Strong Secrets](#generate-strong-secrets)
    - [Default Test Data](#default-test-data)
      - [User Account](#user-account)
      - [OAuth Client](#oauth-client)
    - [Pluggable Token Providers](#pluggable-token-providers)
      - [Architecture](#architecture)
      - [Token Provider Modes](#token-provider-modes)
      - [HTTP API Contract](#http-api-contract)
      - [Why Local Storage is Retained](#why-local-storage-is-retained)
      - [Use Cases](#use-cases)
      - [Migration Path](#migration-path)
    - [Service-to-Service Authentication](#service-to-service-authentication)
      - [Why Service-to-Service Authentication?](#why-service-to-service-authentication)
      - [Authentication Modes](#authentication-modes)
      - [Configuration per Service](#configuration-per-service)
      - [Server-Side Verification Example](#server-side-verification-example)
      - [Example: Securing External Authentication API](#example-securing-external-authentication-api)
    - [HTTP Retry with Exponential Backoff](#http-retry-with-exponential-backoff)
      - [Features](#features-1)
      - [Default Behavior](#default-behavior)
      - [Automatic Retry Conditions](#automatic-retry-conditions)
      - [Configuration](#configuration-1)
      - [Disable Retries](#disable-retries)
      - [Use Cases](#use-cases-1)
      - [Best Practices](#best-practices)
      - [Example: Aggressive Retry Configuration](#example-aggressive-retry-configuration)
      - [Example: Conservative Retry Configuration](#example-conservative-retry-configuration)
      - [Implementation Details](#implementation-details)
  - [AuthGate Architecture](#authgate-architecture)
    - [Project Structure](#project-structure)
    - [Technology Stack](#technology-stack)
  - [Development](#development)
    - [Build Commands](#build-commands)
      - [Build Details](#build-details)
    - [Database Schema](#database-schema)
    - [Extending the Server](#extending-the-server)
      - [Add a new OAuth client](#add-a-new-oauth-client)
      - [Add custom scopes](#add-custom-scopes)
  - [Monitoring and Observability](#monitoring-and-observability)
    - [Health Check Endpoint](#health-check-endpoint)
      - [Health Check Details](#health-check-details)
    - [Monitoring Best Practices](#monitoring-best-practices)
      - [Key Metrics to Monitor](#key-metrics-to-monitor)
      - [Logging](#logging)
  - [Security Considerations](#security-considerations)
    - [Production Deployment Checklist](#production-deployment-checklist)
    - [Threat Model](#threat-model)
      - [What AuthGate Protects Against](#what-authgate-protects-against)
      - [What You Must Secure](#what-you-must-secure)
  - [Deployment](#deployment)
    - [Production Deployment Options](#production-deployment-options)
      - [1. Binary Deployment (Systemd)](#1-binary-deployment-systemd)
      - [2. Docker Deployment](#2-docker-deployment)
      - [3. Reverse Proxy Setup (Nginx)](#3-reverse-proxy-setup-nginx)
      - [4. Cloud Platform Deployment](#4-cloud-platform-deployment)
        - [Fly.io Example](#flyio-example)
  - [Use Cases Sample](#use-cases-sample)
    - [Example: Securing a CLI Tool](#example-securing-a-cli-tool)
    - [Example: IoT Device Authentication](#example-iot-device-authentication)
    - [Example: Security Incident Response](#example-security-incident-response)
  - [Performance Considerations](#performance-considerations)
    - [Scalability](#scalability)
      - [Current Architecture (SQLite)](#current-architecture-sqlite)
      - [For High-Scale Deployments](#for-high-scale-deployments)
      - [Performance Tips](#performance-tips)
    - [Benchmarks (Reference)](#benchmarks-reference)
  - [Comparison with Other Solutions](#comparison-with-other-solutions)
  - [Troubleshooting](#troubleshooting)
    - [Common Issues](#common-issues)
      - [Issue: "Client not found" error](#issue-client-not-found-error)
      - [Issue: Database locked errors](#issue-database-locked-errors)
      - [Issue: "authorization_pending" never resolves](#issue-authorization_pending-never-resolves)
      - [Issue: "Username conflict with existing user" error](#issue-username-conflict-with-existing-user-error)
      - [Issue: JWT signature verification fails](#issue-jwt-signature-verification-fails)
      - [Issue: Session not persisting](#issue-session-not-persisting)
    - [Debug Mode](#debug-mode)
  - [FAQ](#faq)
    - [Q: Why not use OAuth password grant?](#q-why-not-use-oauth-password-grant)
    - [Q: Can I use this in production?](#q-can-i-use-this-in-production)
    - [Q: How do I add user registration?](#q-how-do-i-add-user-registration)
    - [Q: Can I use this with multiple clients?](#q-can-i-use-this-with-multiple-clients)
    - [Q: What about token refresh?](#q-what-about-token-refresh)
    - [Q: How do users revoke device access?](#q-how-do-users-revoke-device-access)
    - [Q: How long do device codes last?](#q-how-long-do-device-codes-last)
    - [Q: Can I use a different database?](#q-can-i-use-a-different-database)
    - [Q: How do I change the polling interval?](#q-how-do-i-change-the-polling-interval)
    - [Q: Are user codes case-sensitive?](#q-are-user-codes-case-sensitive)
  - [Contributing](#contributing)
  - [License](#license)
  - [References](#references)
  - [Acknowledgments](#acknowledgments)

---

## Why AuthGate?

### The Problem

Modern CLI tools and IoT devices need to access user resources securely, but traditional OAuth 2.0 flows weren't designed for them:

- **Authorization Code Flow** requires a browser redirect and a local callback server
- **Client Credentials Flow** can't authenticate specific users
- **Password Grant** requires users to enter credentials directly into apps (security risk)
- Embedding `client_secret` in distributed applications is insecure

### Real-World Scenarios

- 🖥️ **CLI tools** (like `gh`, `aws-cli`) need to access user data
- 📺 **Smart TVs** and streaming devices authenticating streaming services
- 🏠 **IoT devices** that lack browsers or input capabilities
- 🤖 **CI/CD pipelines** and automation scripts requiring user authorization
- 🎮 **Gaming consoles** logging into online services

### The Solution

**Device Authorization Grant (RFC 8628)** solves this by splitting the authorization flow:

1. Device requests a code from the server
2. User visits a URL **on another device** (phone/computer) with a browser
3. User logs in and enters the short code
4. Device polls the server until authorization is complete
5. Device receives an access token

**AuthGate** provides a production-ready implementation of this flow that you can deploy in minutes.

---

## Features

- ✅ **RFC 8628 Compliant** - Full implementation of OAuth 2.0 Device Authorization Grant
- ✅ **RFC 6749 Refresh Tokens** - Full refresh token support with fixed and rotation modes
- ✅ **RFC 7009 Token Revocation** - Secure token revocation endpoint for revoking access
- ✅ **Lightweight** - Single binary, SQLite database, no external dependencies
- ✅ **Easy Configuration** - `.env` file support for all settings
- ✅ **Session-Based Auth** - Secure user login with encrypted cookies (7-day expiry)
- ✅ **JWT Tokens** - Industry-standard access tokens with HMAC-SHA256 signing
- ✅ **Refresh Token Modes** - Fixed (reusable, multi-device friendly) or Rotation (high security)
- ✅ **Token Management** - Status-based token control (active/disabled/revoked)
- ✅ **Session Management** - Web UI for users to view and revoke active sessions
- ✅ **Example CLI** - Complete working example of a client implementation
- ✅ **Token Verification** - Built-in endpoint to validate tokens (`/oauth/tokeninfo`)
- ✅ **Health Check** - Database connection monitoring via `/health` endpoint
- ✅ **Graceful Shutdown** - Proper signal handling for zero-downtime deployments
- ✅ **Embedded Assets** - Templates and static files compiled into binary
- ✅ **Cross-Platform** - Runs on Linux, macOS, Windows
- ✅ **Docker Ready** - Multi-arch images with security best practices
- ✅ **Static Binaries** - CGO-free builds for easy deployment
- ✅ **Pluggable Token Providers** - Use local JWT or delegate to external token services
- ✅ **Hybrid Authentication** - Support both local and external authentication providers
- ✅ **HTTP Retry with Exponential Backoff** - Automatic retry for external API calls with configurable backoff

---

## Quick Start

### Prerequisites

- Go 1.24 or higher
- Make (optional, but recommended for convenience commands)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd authgate

# Copy environment configuration
cp .env.example .env

# Edit .env and set your secrets
nano .env

# Build the server (outputs to bin/authgate with version info)
make build

# Or build directly with Go
go build -o bin/authgate .
```

### Run the Server

```bash
# Show version information
./bin/authgate -v
./bin/authgate --version

# Show help
./bin/authgate -h

# Start the server
./bin/authgate server

# Or directly with Go
go run . server
```

The server will start on `http://localhost:8080` by default.

**Important:** Note the `client_id` printed in the startup logs - you'll need this for the CLI example.

### Docker Deployment

AuthGate provides multi-architecture Docker images for easy deployment:

```bash
# Build for your platform
make build_linux_amd64  # For Linux x86_64
make build_linux_arm64  # For Linux ARM64

# Build Docker image (with version tag)
docker build -f docker/Dockerfile \
  --build-arg VERSION=v1.0.0 \
  -t authgate:v1.0.0 \
  -t authgate:latest \
  .

# Or build without version (defaults to "dev")
docker build -f docker/Dockerfile -t authgate .

# Run with Docker
docker run -d \
  --name authgate \
  -p 8080:8080 \
  -v authgate-data:/app/data \
  -e JWT_SECRET=your-secret-here \
  -e SESSION_SECRET=your-session-secret \
  -e BASE_URL=http://localhost:8080 \
  authgate

# Check health
curl http://localhost:8080/health

# Inspect image labels to verify version
docker inspect authgate:v1.0.0 | grep -A 5 Labels
```

#### Docker Features

- Alpine-based (minimal attack surface)
- Multi-architecture support (amd64, arm64)
- Runs as non-root user (UID 1000)
- Built-in health check endpoint
- Persistent volume for SQLite database
- Embedded templates and static files (single binary)
- Version labels via `--build-arg VERSION=<version>` (supports both OCI and Label Schema standards)

#### Docker Compose Example

```yaml
version: "3.8"

services:
  authgate:
    image: authgate:latest
    container_name: authgate
    ports:
      - "8080:8080"
    volumes:
      - authgate-data:/app/data
    environment:
      - BASE_URL=https://auth.yourdomain.com
      - JWT_SECRET=${JWT_SECRET}
      - SESSION_SECRET=${SESSION_SECRET}
      - DATABASE_PATH=/app/data/oauth.db
    restart: unless-stopped
    healthcheck:
      test:
        [
          "CMD",
          "wget",
          "--no-verbose",
          "--tries=1",
          "--spider",
          "http://localhost:8080/health",
        ]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

volumes:
  authgate-data:
```

### Test with the Example CLI

```bash
cd _example/authgate-cli

# Configure the client
cp .env.example .env
nano .env  # Add the CLIENT_ID from server logs

# Run the CLI
go run main.go
```

The CLI demonstrates:

1. **First Run (Device Flow)**:
   - Requests a device code
   - Displays a URL and user code
   - Waits for authorization
   - Receives access token + refresh token
   - Saves tokens to `.authgate-tokens.json`
   - Verifies the token

2. **Subsequent Runs (Token Reuse)**:
   - Loads existing tokens from file
   - Uses access token if still valid
   - Automatically refreshes if expired
   - Saves refreshed tokens

3. **Automatic Refresh Demo**:
   - Makes API call with automatic 401 handling
   - Refreshes token and retries on authentication failure

**Token Storage**: Tokens are securely saved to `.authgate-tokens.json` (excluded from git) with file permissions 0600 (read/write for owner only)

---

## User Interface

AuthGate provides a clean, modern web interface for user authentication and device authorization. Below are screenshots of the complete authorization flow:

### 1. Login Page

![Login Page](images/login-page.png)

Users are prompted to sign in with their credentials before authorizing any device. The login page features:

- Simple username and password authentication
- Clear call-to-action: "Sign in to authorize your device"
- Responsive design that works on both desktop and mobile browsers

### 2. Device Authorization Page

![Device Authorization](images/device-page.png)

After successful login, users see the device authorization page where they:

- Enter the code displayed on their CLI tool or device
- See their current logged-in status with a logout option
- Submit the code with a clear "Authorize Device" button
- Code format: `XXXX-XXXX` (8 characters, case-insensitive)

### 3. Authorization Success

![Authorization Successful](images/authorization-successful.png)

Upon successful authorization, users receive confirmation with:

- Visual success indicator (green checkmark)
- Confirmation message showing which client was authorized
- Clear instructions to return to their CLI tool
- Option to authorize additional devices without re-login
- Logout button for security

### 4. Session Management

After logging in, users can manage their active sessions by clicking the "Active Sessions" link on the device authorization page. The session management interface provides:

- **View All Active Sessions** - See all devices that have been authorized with your account
- **Client Information** - Display client name and ID for easy identification
- **Session Details** - View creation time, expiration time, and granted scopes
- **Individual Revocation** - Revoke specific device access with one click
- **Revoke All** - Sign out all devices simultaneously for security
- **Status Indicators** - Visual display of active vs. expired sessions

This feature gives users complete control over which devices can access their account, enhancing security and transparency.

---

## How It Works

### Device Flow Sequence

```mermaid
sequenceDiagram
    participant CLI as CLI Tool
    participant AuthGate as AuthGate Server
    participant User as User (Browser)

    Note over CLI,User: Phase 1: Device Code Request
    CLI->>+AuthGate: POST /oauth/device/code<br/>(client_id)
    AuthGate-->>-CLI: device_code, user_code<br/>verification_uri

    Note over CLI: Display to user:<br/>"Visit http://..../device"<br/>"Enter code: 12345678"

    Note over CLI,User: Phase 2: User Authorization
    User->>+AuthGate: GET /device
    AuthGate-->>-User: Login page (if not authenticated)

    User->>+AuthGate: POST /login<br/>(username, password)
    AuthGate-->>-User: Redirect to /device<br/>(session created)

    User->>+AuthGate: GET /device<br/>(show code entry form)
    AuthGate-->>-User: Code entry page

    User->>+AuthGate: POST /device/verify<br/>(user_code: 12345678)
    AuthGate-->>-User: Success page

    Note over CLI,User: Phase 3: Token Polling
    CLI->>+AuthGate: POST /oauth/token<br/>(device_code, polling)
    AuthGate-->>-CLI: {"error": "authorization_pending"}

    Note over CLI: Wait 5 seconds

    CLI->>+AuthGate: POST /oauth/token<br/>(device_code, polling)
    AuthGate-->>-CLI: {"access_token": "eyJ...",<br/>"token_type": "Bearer",<br/>"expires_in": 3600}

    Note over CLI: Authentication complete!<br/>Store and use access token
```

### Key Endpoints

| Endpoint                       | Method   | Auth Required | Purpose                                                             |
| ------------------------------ | -------- | ------------- | ------------------------------------------------------------------- |
| `/health`                      | GET      | No            | Health check with database connection test                          |
| `/oauth/device/code`           | POST     | No            | Request device and user codes (CLI/device)                          |
| `/oauth/token`                 | POST     | No            | Token endpoint (grant_type=device_code or grant_type=refresh_token) |
| `/oauth/tokeninfo`             | GET      | No            | Verify token validity (pass token as query)                         |
| `/oauth/revoke`                | POST     | No            | Revoke access token (RFC 7009)                                      |
| `/device`                      | GET      | Yes (Session) | User authorization page (browser)                                   |
| `/device/verify`               | POST     | Yes (Session) | Complete authorization (submit user_code)                           |
| `/account/sessions`            | GET      | Yes (Session) | View all active sessions                                            |
| `/account/sessions/:id/revoke` | POST     | Yes (Session) | Revoke specific session                                             |
| `/account/sessions/revoke-all` | POST     | Yes (Session) | Revoke all user sessions                                            |
| `/login`                       | GET/POST | No            | User login (creates session)                                        |
| `/logout`                      | GET      | Yes (Session) | User logout (destroys session)                                      |

#### Endpoint Details

##### Device Flow (CLI)

- `POST /oauth/device/code` - Returns `device_code`, `user_code`, `verification_uri`, `interval` (5s)
- `POST /oauth/token` - Token endpoint supporting multiple grant types:
  - **Device Code Grant**: `grant_type=urn:ietf:params:oauth:grant-type:device_code`
    - Poll with `device_code` and `client_id`
    - Returns `access_token`, `refresh_token`, `token_type`, `expires_in`, `scope`
    - Returns `authorization_pending` error while waiting for user
  - **Refresh Token Grant**: `grant_type=refresh_token`
    - Request with `refresh_token`, `client_id`, and optional `scope`
    - Returns new `access_token` (fixed mode) or new `access_token` + `refresh_token` (rotation mode)
    - Returns `invalid_grant` error if refresh token is invalid/expired

##### User Authorization (Browser)

- `GET /device` - Shows code entry form (redirects to `/login` if not authenticated)
- `POST /device/verify` - Validates and approves user code (requires valid session)

##### Token Validation

- `GET /oauth/tokeninfo?access_token=<JWT>` - Returns token details or error

##### Token Revocation (RFC 7009)

- `POST /oauth/revoke` - Revoke access token (CLI)
  - Parameters: `token` (required) - The JWT token to revoke
  - Parameters: `token_type_hint` (optional) - Set to "access_token"
  - Returns: HTTP 200 on success (even if token doesn't exist, per RFC 7009)
  - Note: Prevents token scanning attacks by always returning success

##### Session Management (Web UI)

- `GET /account/sessions` - View all active sessions for current user
  - Displays: Client name, Client ID, scopes, creation/expiration times, status
  - Requires: Valid user session (login required)

- `POST /account/sessions/:id/revoke` - Revoke specific session
  - Parameters: `:id` - Token ID to revoke
  - Requires: Valid user session, token must belong to current user
  - Returns: Redirect to sessions page

- `POST /account/sessions/revoke-all` - Sign out all devices
  - Revokes all access tokens for the current user
  - Useful for security incidents or password changes
  - Returns: Redirect to sessions page

**Security Note:** Session management endpoints use CSRF protection and verify token ownership before revocation.

---

## Configuration

### Environment Variables

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
```

#### Generate Strong Secrets

```bash
# Generate JWT_SECRET (64 characters recommended)
openssl rand -hex 32

# Generate SESSION_SECRET (64 characters recommended)
openssl rand -hex 32

# Or use this one-liner to update .env
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env
echo "SESSION_SECRET=$(openssl rand -hex 32)" >> .env
```

### Default Test Data

The server initializes with default test accounts:

#### User Account

- Username: `admin`
- Password: Auto-generated 16-character random password (shown in server logs on first run)

#### OAuth Client

- Name: `AuthGate CLI`
- Client ID: Auto-generated UUID (shown in server logs)

**⚠️ Security Warning:** Note the admin password from server logs on first run and change it in production!

### Pluggable Token Providers

AuthGate supports **pluggable token providers** for JWT generation and validation, allowing you to delegate token operations to external services while maintaining local token management.

#### Architecture

- **Token Generation & Validation**: Can be handled locally or by external HTTP API
- **Local Storage**: Token records are always stored in local database for management (revocation, listing, auditing)
- **Configuration**: Global mode selection via `TOKEN_PROVIDER_MODE` environment variable

#### Token Provider Modes

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

#### HTTP API Contract

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

#### Why Local Storage is Retained

Even when using external token providers, AuthGate stores token records locally for:

1. **Revocation**: Users can revoke tokens via `/account/sessions` or `/oauth/revoke`
2. **Management**: Users can list their active sessions
3. **Auditing**: Track when and for which clients tokens were issued
4. **Client Association**: Link tokens to OAuth clients

#### Use Cases

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

#### Migration Path

1. Start with `TOKEN_PROVIDER_MODE=local` (default)
2. Test thoroughly
3. Set up external token service
4. Switch to `TOKEN_PROVIDER_MODE=http_api`
5. Monitor logs for errors
6. Can rollback to local mode without data loss

### Service-to-Service Authentication

When AuthGate connects to external HTTP APIs (for authentication or token operations), you can secure these service-to-service communications with authentication headers.

#### Why Service-to-Service Authentication?

External HTTP API providers (authentication and token services) need to verify that incoming requests are from a trusted AuthGate instance. Without authentication, these endpoints would be vulnerable to unauthorized access.

#### Authentication Modes

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

#### Configuration per Service

Authentication is configured **separately** for each external service:

| Environment Variable    | Purpose                           | Service       |
| ----------------------- | --------------------------------- | ------------- |
| `HTTP_API_AUTH_MODE`    | Auth mode for user authentication | HTTP API Auth |
| `HTTP_API_AUTH_SECRET`  | Shared secret for authentication  | HTTP API Auth |
| `HTTP_API_AUTH_HEADER`  | Custom header name (simple mode)  | HTTP API Auth |
| `TOKEN_API_AUTH_MODE`   | Auth mode for token operations    | Token API     |
| `TOKEN_API_AUTH_SECRET` | Shared secret for token API       | Token API     |
| `TOKEN_API_AUTH_HEADER` | Custom header name (simple mode)  | Token API     |

#### Server-Side Verification Example

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

#### Example: Securing External Authentication API

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

### HTTP Retry with Exponential Backoff

AuthGate includes automatic HTTP retry capabilities for all external API communications (authentication and token operations) to improve reliability and resilience against transient network failures.

#### Features

- **Automatic Retries**: Failed HTTP requests are automatically retried with configurable attempts
- **Exponential Backoff**: Retry delays increase exponentially to avoid overwhelming failing services
- **Smart Retry Logic**: Only retries on appropriate errors (network failures, 5xx errors, 429 rate limits)
- **Non-Blocking**: Retries respect context cancellation and timeouts

#### Default Behavior

By default, AuthGate retries failed requests up to 3 times with the following pattern:

- **Initial delay**: 1 second
- **Maximum delay**: 10 seconds
- **Multiplier**: 2.0x (exponential backoff)

Example retry sequence:

1. First attempt fails → wait 1s
2. Second attempt fails → wait 2s
3. Third attempt fails → wait 4s
4. Fourth attempt fails → return error

#### Automatic Retry Conditions

Requests are automatically retried on:

- Network errors (connection failures, timeouts, DNS issues)
- HTTP 5xx server errors (500, 502, 503, 504)
- HTTP 429 (Too Many Requests)

Requests are **not** retried on:

- HTTP 4xx client errors (except 429)
- HTTP 2xx/3xx successful responses
- Context cancellation or timeout

#### Configuration

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

#### Disable Retries

To disable retries (not recommended for production):

```bash
HTTP_API_MAX_RETRIES=0
TOKEN_API_MAX_RETRIES=0
```

#### Use Cases

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

#### Best Practices

1. **Production Settings**: Use default retry settings (3 retries) for most production scenarios
2. **High-Traffic Environments**: Consider increasing `MAX_RETRY_DELAY` to 30s-60s to avoid overwhelming recovering services
3. **Low-Latency Requirements**: Reduce `MAX_RETRIES` to 1-2 for time-sensitive operations
4. **Monitoring**: Track retry rates to identify unreliable external services
5. **Timeouts**: Ensure `HTTP_API_TIMEOUT` and `TOKEN_API_TIMEOUT` are set appropriately to account for retries

#### Example: Aggressive Retry Configuration

For critical services where availability is paramount:

```bash
# Retry up to 10 times with longer delays
HTTP_API_MAX_RETRIES=10
HTTP_API_RETRY_DELAY=500ms
HTTP_API_MAX_RETRY_DELAY=60s
HTTP_API_TIMEOUT=120s  # Increase timeout to accommodate retries
```

#### Example: Conservative Retry Configuration

For fast-fail scenarios where latency matters more than resilience:

```bash
# Retry only once with short delays
HTTP_API_MAX_RETRIES=1
HTTP_API_RETRY_DELAY=500ms
HTTP_API_MAX_RETRY_DELAY=2s
HTTP_API_TIMEOUT=15s
```

#### Implementation Details

- Built using [go-httpretry v0.1.0](https://github.com/appleboy/go-httpretry)
- Retry logic wraps the authentication-enabled HTTP client
- All authentication headers (Simple, HMAC) are preserved across retries
- Request bodies are cloned for retries to avoid consumed stream issues

---

## AuthGate Architecture

### Project Structure

```txt
authgate/
├── config/          # Configuration management (environment variables, defaults)
├── handlers/        # HTTP request handlers
│   ├── auth.go      # User login/logout endpoints
│   ├── device.go    # Device authorization flow (/device, /device/verify)
│   ├── token.go     # Token issuance (/oauth/token), verification (/oauth/tokeninfo), and revocation (/oauth/revoke)
│   ├── session.go   # Session management (/account/sessions)
│   └── client.go    # Admin client management
├── middleware/      # HTTP middleware
│   ├── auth.go      # Session authentication (RequireAuth, RequireAdmin)
│   └── csrf.go      # CSRF protection middleware
├── models/          # Data models
│   ├── user.go      # User accounts
│   ├── client.go    # OAuth clients (OAuthClient)
│   ├── device.go    # Device codes (DeviceCode)
│   └── token.go     # Access tokens (AccessToken)
├── auth/            # Authentication providers (pluggable design)
│   ├── local.go     # Local authentication (database)
│   └── http_api.go  # External HTTP API authentication
├── token/           # Token providers (pluggable design)
│   ├── types.go     # Shared data structures (TokenResult, TokenValidationResult)
│   ├── errors.go    # Provider-level error definitions
│   ├── local.go     # Local JWT provider (HMAC-SHA256)
│   └── http_api.go  # External HTTP API token provider
├── services/        # Business logic layer (depends on store and providers)
│   ├── user.go      # User management (integrates auth providers)
│   ├── device.go    # Device code generation and validation
│   ├── token.go     # Token service (integrates token providers)
│   └── client.go    # OAuth client management
├── store/           # Database layer (GORM)
│   ├── driver.go    # Database driver factory (SQLite, PostgreSQL)
│   └── sqlite.go    # Database initialization, migrations, seed data, batch queries
├── templates/       # HTML templates (embedded via go:embed)
│   ├── account/     # User account templates
│   │   └── sessions.html  # Active sessions management page
│   └── admin/       # Admin panel templates
├── static/          # Static files (embedded via go:embed)
├── docker/          # Docker configuration
│   └── Dockerfile   # Alpine-based multi-arch image
├── _example/        # Example CLI client implementation
│   └── authgate-cli/
├── version/         # Version information (embedded at build time)
├── Makefile         # Build automation and targets
├── main.go          # Application entry point and router setup
├── .env.example     # Environment configuration template
└── CLAUDE.md        # AI assistant guidance (optional)
```

### Technology Stack

- **Web Framework:** [Gin](https://gin-gonic.com/) - Fast HTTP router
- **ORM:** [GORM](https://gorm.io/) - Database abstraction
- **Database:** SQLite - Embedded database
- **Sessions:** [gin-contrib/sessions](https://github.com/gin-contrib/sessions) - Cookie sessions
- **JWT:** [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - Token generation
- **Config:** [joho/godotenv](https://github.com/joho/godotenv) - Environment management

---

## Development

### Build Commands

```bash
# Build binary with version info (outputs to bin/authgate)
make build

# Install binary to $GOPATH/bin
make install

# Run tests with coverage report (generates coverage.txt)
make test

# Run linter (auto-installs golangci-lint if missing)
make lint

# Format code with golangci-lint
make fmt

# Cross-compile for Linux
make build_linux_amd64  # Static binary (CGO_ENABLED=0)
make build_linux_arm64  # Static binary (CGO_ENABLED=0)

# Clean build artifacts and coverage
make clean

# Show all available targets
make help
```

#### Build Details

- Version information is automatically embedded using git tags/commits
- LDFLAGS includes: Version, BuildTime, GitCommit, GoVersion, BuildOS, BuildArch
- Cross-compiled binaries are statically linked (no external dependencies)
- Output locations: `bin/` for local builds, `release/<os>/<arch>/` for cross-compilation

### Database Schema

The application automatically creates these tables:

- `users` - User accounts
- `oauth_clients` - Registered client applications
- `device_codes` - Active device authorization requests
- `access_tokens` - Issued JWT tokens

### Extending the Server

#### Add a new OAuth client

```go
client := &models.OAuthClient{
    Name:         "My App",
    ClientID:     uuid.New().String(),
    RedirectURIs: "http://localhost:3000/callback",
}
db.Create(client)
```

#### Add custom scopes

Modify `services/device.go` to validate and store additional scopes.

---

## Monitoring and Observability

### Health Check Endpoint

```bash
# Basic health check
curl http://localhost:8080/health

# Response format (JSON)
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2026-01-07T10:00:00Z"
}
```

#### Health Check Details

- Tests database connectivity with a ping
- Returns HTTP 200 on success, 503 on database failure
- Used by Docker HEALTHCHECK directive
- Recommended monitoring interval: 30 seconds

### Monitoring Best Practices

#### Key Metrics to Monitor

- Health check endpoint availability
- Database file size growth
- Active device codes count
- Issued tokens per hour
- Session count
- HTTP response times
- Failed login attempts

#### Logging

- Gin framework logs all HTTP requests
- Include request ID for tracing
- Log authentication failures for security monitoring

---

## Security Considerations

### Production Deployment Checklist

- [ ] Change `JWT_SECRET` to a strong random value (32+ characters)
- [ ] Change `SESSION_SECRET` to a strong random value (32+ characters)
- [ ] Use HTTPS (set `BASE_URL` to `https://...`)
- [ ] Change default admin user password (check server logs for initial random password)
- [ ] Set appropriate `DeviceCodeExpiration` (default: 30 minutes)
- [ ] Set appropriate `JWTExpiration` (default: 1 hour)
- [ ] Configure firewall rules
- [ ] Enable rate limiting for token polling and revocation endpoints
- [ ] Regularly backup `oauth.db`
- [ ] Set up automated cleanup for expired tokens and device codes
- [ ] Use Docker non-root user mode (already configured)
- [ ] Configure timeouts for HTTP server (ReadTimeout, WriteTimeout)
- [ ] Enable CORS policies if needed
- [ ] Monitor `/health` endpoint for service availability
- [ ] Educate users to use `/account/sessions` to review and revoke suspicious devices

### Threat Model

#### What AuthGate Protects Against

- ✅ Client secret exposure in distributed apps
- ✅ Phishing attacks (user authorizes on trusted domain)
- ✅ Replay attacks (device codes are single-use)
- ✅ Token tampering (JWT signature verification)

#### What You Must Secure

- 🔒 Server host security
- 🔒 Database encryption at rest
- 🔒 TLS/HTTPS in production
- 🔒 Secret rotation policies

---

## Deployment

### Production Deployment Options

#### 1. Binary Deployment (Systemd)

```bash
# Build static binary
make build_linux_amd64

# Copy to server
scp release/linux/amd64/authgate user@server:/usr/local/bin/

# Create systemd service
cat > /etc/systemd/system/authgate.service <<EOF
[Unit]
Description=AuthGate OAuth Server
After=network.target

[Service]
Type=simple
User=authgate
WorkingDirectory=/var/lib/authgate
ExecStart=/usr/local/bin/authgate server
Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/authgate

# Environment
EnvironmentFile=/etc/authgate/.env

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl enable authgate
systemctl start authgate
```

#### 2. Docker Deployment

```bash
# Build with version information
VERSION=$(git describe --tags --always --dirty)
docker build -f docker/Dockerfile \
  --build-arg VERSION=${VERSION} \
  -t authgate:${VERSION} \
  -t authgate:latest \
  .

# Using Docker Compose (recommended)
docker-compose up -d

# Or standalone Docker
docker run -d \
  --name authgate \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /var/lib/authgate:/app/data \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  -e SESSION_SECRET=$(openssl rand -hex 32) \
  -e BASE_URL=https://auth.yourdomain.com \
  authgate:latest

# Verify deployed version
docker inspect authgate:latest --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
```

#### 3. Reverse Proxy Setup (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

#### 4. Cloud Platform Deployment

##### Fly.io Example

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Launch app
fly launch

# Set secrets
fly secrets set JWT_SECRET=$(openssl rand -hex 32)
fly secrets set SESSION_SECRET=$(openssl rand -hex 32)

# Deploy
fly deploy
```

---

## Use Cases Sample

### Example: Securing a CLI Tool

Your CLI tool needs to access a protected API:

1. **Server Setup:** Deploy AuthGate with your custom client
2. **CLI Integration:** Use the device flow to get user tokens
3. **API Calls:** Include the JWT in `Authorization: Bearer <token>` headers
4. **Token Refresh:** Store tokens securely, implement refresh logic

### Example: IoT Device Authentication

Your smart device needs user authorization:

1. Device displays a short code on its screen
2. User visits the URL on their phone
3. User logs in and enters the code
4. Device receives token and can now access user's account
5. Token stored securely in device memory

### Example: Security Incident Response

When a user suspects unauthorized access:

1. **User logs in** to the web interface
2. **Reviews active sessions** at `/account/sessions`
3. **Identifies suspicious devices** by checking client names and authorization times
4. **Revokes specific sessions** for unrecognized devices
5. **Or revokes all sessions** if multiple devices are compromised
6. **Re-authorizes legitimate devices** after security review

This workflow gives users complete control and visibility over their device authorizations, meeting modern security and privacy expectations.

---

## Performance Considerations

### Scalability

#### Current Architecture (SQLite)

- Suitable for: Small to medium deployments (< 1000 concurrent devices)
- Limitations: SQLite write locks can cause contention under heavy load
- Recommended: Monitor database file size and query performance

#### For High-Scale Deployments

AuthGate now supports PostgreSQL natively. Simply configure via environment variables:

```bash
# .env configuration
DATABASE_DRIVER=postgres
DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=require"
```

No code changes required! The application automatically selects the appropriate driver based on your configuration.

#### Performance Tips

- Enable SQLite WAL mode for better concurrent read performance
- Add indexes on frequently queried columns (`device_code`, `user_code`, `client_id`)
- Implement connection pooling for PostgreSQL
- Use Redis for session storage instead of cookies
- Add caching layer for token validation
- Clean up expired device codes and tokens regularly
- **Batch Queries:** Session management uses `WHERE IN` queries to avoid N+1 problems when fetching client information

### Benchmarks (Reference)

**Hardware:** 2-core CPU, 4GB RAM, SSD
**Test:** 100 concurrent device authorization flows

| Metric               | SQLite | PostgreSQL |
| -------------------- | ------ | ---------- |
| Requests/sec         | ~500   | ~2000      |
| Avg Response Time    | 20ms   | 5ms        |
| P95 Response Time    | 50ms   | 15ms       |
| Database Size (1000) | 2MB    | 5MB        |

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

---

## Troubleshooting

### Common Issues

#### Issue: "Client not found" error

```bash
# Solution: Check that CLIENT_ID in your CLI .env matches the server logs
# Server logs show: "Seeded OAuth client with ID: abc-123-def"
```

#### Issue: Database locked errors

```bash
# Solution: Ensure only one instance is running, or use WAL mode
# SQLite doesn't handle high concurrency well - consider PostgreSQL for production
```

#### Issue: "authorization_pending" never resolves

```bash
# Solution: Check that the user completed authorization in browser
# Verify the user_code was entered correctly (case-insensitive, dashes ignored)
# Check server logs for errors during authorization
```

#### Issue: "Username conflict with existing user" error

**Problem**: User sees "Username conflict with existing user. Please contact administrator." when logging in via external API.

**Cause**: The username returned by the external authentication API matches an existing user in the local database.

**Resolution Options**:

1. **Rename existing local user** (if it's a different person):

   ```sql
   UPDATE users SET username = 'newname' WHERE username = 'conflicting-username';
   ```

2. **Configure external API to use different username**: Update the external system to return a unique username (e.g., append domain suffix).

3. **Manual account merge** (if it's the same person):
   - Ensure the local user has `auth_source='http_api'` and correct `external_id`
   - Recommended for migrating local users to external authentication

**Prevention**: Use namespaced usernames in external API (e.g., [john@company.com](mailto:john@company.com) instead of "john").

#### Issue: JWT signature verification fails

```bash
# Solution: Ensure JWT_SECRET is the same across restarts
# Don't change JWT_SECRET while tokens are still valid
```

#### Issue: Session not persisting

```bash
# Solution: Ensure SESSION_SECRET is set
# Check that cookies are enabled in browser
# Verify BASE_URL matches the domain you're accessing
```

### Debug Mode

Enable debug logging by setting Gin to debug mode:

```bash
GIN_MODE=debug ./bin/authgate server
```

---

## FAQ

### Q: Why not use OAuth password grant?

A: Password grant requires users to enter credentials directly into your app, which trains users to trust third parties with passwords (security anti-pattern).

### Q: Can I use this in production?

A: Yes, but ensure you follow the security checklist and harden the deployment. This is a reference implementation - audit it for your specific needs.

### Q: How do I add user registration?

A: Implement registration handlers in `handlers/auth.go` and update the database schema in `models/user.go`.

### Q: Can I use this with multiple clients?

A: Yes! Add additional clients to the `oauth_clients` table with unique `client_id` values. Each client can have different redirect URIs.

### Q: What about token refresh?

A: AuthGate now fully supports refresh tokens (RFC 6749) with two modes:

- **Fixed Mode (Default)**: Refresh tokens are reusable, perfect for multi-device scenarios. Each device gets its own refresh token that remains valid until manually revoked or expired. Users can manage all tokens via `/account/sessions`.

- **Rotation Mode**: High-security mode where each refresh returns new tokens and old ones are revoked. Enable with `ENABLE_TOKEN_ROTATION=true`.

**Usage Example:**

```bash
# Initial authorization returns both tokens
POST /oauth/token
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  device_code=xxx
  client_id=xxx
→ Returns: access_token + refresh_token

# When access token expires, refresh it
POST /oauth/token
  grant_type=refresh_token
  refresh_token=xxx
  client_id=xxx
→ Returns: new access_token (fixed mode) or access_token + refresh_token (rotation mode)
```

Configure via environment variables:

- `REFRESH_TOKEN_EXPIRATION=720h` (default: 30 days)
- `ENABLE_REFRESH_TOKENS=true` (default)
- `ENABLE_TOKEN_ROTATION=false` (default: fixed mode)

### Q: How do users revoke device access?

A: Users have multiple options to revoke access:

- **Web UI:** Visit `/account/sessions` to view and revoke individual devices
- **CLI/API:** Call `POST /oauth/revoke` with the token parameter (RFC 7009)
- **Revoke All:** Use the "Revoke All" button on the sessions page to sign out all devices at once

### Q: How long do device codes last?

A: Device codes expire after 30 minutes by default. This is configurable via `Config.DeviceCodeExpiration`.

### Q: Can I use a different database?

A: Yes! AuthGate supports both SQLite and PostgreSQL out of the box:

**SQLite** (default):

```bash
DATABASE_DRIVER=sqlite
DATABASE_DSN=oauth.db
```

**PostgreSQL**:

```bash
DATABASE_DRIVER=postgres
DATABASE_DSN="host=localhost user=authgate password=secret dbname=authgate port=5432 sslmode=disable"
```

The database driver uses a factory pattern and can be extended to support MySQL or other databases. See `internal/store/driver.go` for implementation details.

### Q: How do I change the polling interval?

A: The polling interval is 5 seconds by default (RFC 8628 compliant). Modify `Config.PollingInterval` in `config/config.go`.

### Q: Are user codes case-sensitive?

A: No, user codes are normalized to uppercase and dashes are removed before lookup (e.g., "ABCD-1234" = "abcd1234" = "ABCD1234").

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## References

- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [RFC 6749 - OAuth 2.0 Framework (Refresh Tokens)](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7009 - OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [OAuth 2.0 Documentation](https://oauth.net/2/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

## Acknowledgments

Built with ❤️ using:

- [Gin Web Framework](https://gin-gonic.com/)
- [GORM](https://gorm.io/)
- [golang-jwt](https://github.com/golang-jwt/jwt)

---

**Need Help?** Open an issue or check the `_example/` directory for working client code.
