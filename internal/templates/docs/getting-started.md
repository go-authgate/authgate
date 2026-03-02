# Getting Started with AuthGate

AuthGate is an OAuth 2.0 authorization server that enables secure, passwordless authentication for CLI tools, IoT devices, web apps, and mobile applications — without embedding client secrets.

## What is AuthGate?

AuthGate implements two core OAuth 2.0 flows:

- **Device Authorization Grant (RFC 8628)** — ideal for CLI tools, scripts, and headless environments where opening a browser programmatically is inconvenient or impossible.
- **Authorization Code Flow + PKCE (RFC 7636)** — the recommended flow for web and mobile applications.

## Quick Setup

### 1. Start the Server

```bash
./authgate server
```

On first run, AuthGate seeds a default `admin` user and an `AuthGate CLI` OAuth client. The randomly generated password and client ID are printed to the server logs.

### 2. Configure Your Client

Log in to the admin panel and navigate to **Admin → OAuth Clients** to:

- View the auto-generated `AuthGate CLI` client and its `client_id`
- Create new clients for your applications
- Choose between **Device Flow** and **Authorization Code Flow** per client

### 3. Authenticate

Depending on your use case, pick the appropriate flow:

| Use Case           | Recommended Flow           |
| ------------------ | -------------------------- |
| CLI tool or script | Device Authorization Grant |
| Web application    | Authorization Code + PKCE  |
| Mobile application | Authorization Code + PKCE  |
| Server-to-server   | Client Credentials         |

## Core Concepts

### OAuth Clients

Every application that wants to authenticate via AuthGate needs a registered **OAuth Client**. Clients have:

- A unique `client_id`
- An optional `client_secret` (for confidential clients only)
- Configured allowed redirect URIs
- Enabled grant types (device flow, auth code flow, or both)

### Tokens

After a successful authentication, AuthGate issues:

- **Access Token** — a short-lived JWT (default: 1 hour) used to access protected resources
- **Refresh Token** — a longer-lived token used to obtain new access tokens without re-authentication

### Scopes

Scopes define the level of access a client is requesting. Users see a consent screen listing the requested scopes before approving access.

## Configuration

AuthGate is configured via environment variables. Copy `.env.example` to `.env` and set:

```bash
# Required
JWT_SECRET=<generate with: openssl rand -hex 32>
SESSION_SECRET=<generate with: openssl rand -hex 32>
BASE_URL=https://your-domain.com

# Database (default: SQLite)
DATABASE_DRIVER=sqlite
DATABASE_DSN=authgate.db
```

See the full configuration reference in `.env.example`.

## Next Steps

- [Device Authorization Flow](./device-flow) — Learn how CLI and headless clients authenticate
- [Authorization Code Flow](./auth-code-flow) — Learn how web and mobile apps authenticate
