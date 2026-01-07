# AuthGate

> A lightweight OAuth 2.0 Device Authorization Grant server for CLI tools and browserless devices

[![Security Scanning](https://github.com/appleboy/authgate/actions/workflows/security.yml/badge.svg)](https://github.com/appleboy/authgate/actions/workflows/security.yml)
[![Lint and Testing](https://github.com/appleboy/authgate/actions/workflows/testing.yml/badge.svg)](https://github.com/appleboy/authgate/actions/workflows/testing.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

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
- ✅ **Lightweight** - Single binary, SQLite database, no external dependencies
- ✅ **Easy Configuration** - `.env` file support for all settings
- ✅ **Session-Based Auth** - Secure user login with encrypted cookies
- ✅ **JWT Tokens** - Industry-standard access tokens
- ✅ **Example CLI** - Complete working example of a client implementation
- ✅ **Token Verification** - Built-in endpoint to validate tokens
- ✅ **Cross-Platform** - Runs on Linux, macOS, Windows

---

## Quick Start

### Prerequisites

- Go 1.24 or higher
- Make (optional, for convenience commands)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd authgate

# Copy environment configuration
cp .env.example .env

# Edit .env and set your secrets
nano .env

# Build the server
make build

# Or build directly
go build -o authgate .
```

### Run the Server

```bash
./authgate
```

The server will start on `http://localhost:8080` by default.

**Important:** Note the `client_id` printed in the startup logs - you'll need this for the CLI example.

### Test with the Example CLI

```bash
cd _example/authgate-cli

# Configure the client
cp .env.example .env
nano .env  # Add the CLIENT_ID from server logs

# Run the CLI
go run main.go
```

The CLI will:

1. Request a device code
2. Display a URL and user code
3. Wait for you to authorize
4. Receive an access token
5. Verify the token

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

| Endpoint             | Method   | Purpose                                    |
| -------------------- | -------- | ------------------------------------------ |
| `/health`            | GET      | Health check with database connection test |
| `/oauth/device/code` | POST     | Request device and user codes              |
| `/oauth/token`       | POST     | Poll for access token                      |
| `/oauth/tokeninfo`   | GET      | Verify token validity                      |
| `/device`            | GET      | User authorization page                    |
| `/device/verify`     | POST     | Complete authorization                     |
| `/login`             | GET/POST | User login                                 |
| `/logout`            | GET      | User logout                                |

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Server Configuration
SERVER_ADDR=:8080
BASE_URL=http://localhost:8080

# Security - CHANGE THESE IN PRODUCTION!
JWT_SECRET=your-256-bit-secret-change-in-production
SESSION_SECRET=session-secret-change-in-production

# Database
DATABASE_PATH=oauth.db
```

### Default Test Data

The server initializes with default test accounts:

**User Account:**

- Username: `admin`
- Password: `password123`

**OAuth Client:**

- Name: `AuthGate CLI`
- Client ID: Auto-generated UUID (shown in server logs)

**⚠️ Security Warning:** Change these in production!

---

## Architecture

### Project Structure

```txt
OAuth/
├── config/          # Configuration management
├── handlers/        # HTTP request handlers
│   ├── auth.go      # User login/logout
│   ├── device.go    # Device authorization flow
│   └── token.go     # Token issuance and verification
├── middleware/      # HTTP middleware (auth, logging)
├── models/          # Data models (User, Client, DeviceCode, Token)
├── services/        # Business logic
│   ├── auth.go      # User authentication
│   ├── device.go    # Device code generation
│   └── token.go     # JWT creation and validation
├── store/           # Database layer (GORM + SQLite)
├── templates/       # HTML templates
├── _example/        # Example CLI implementation
└── main.go          # Application entry point
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
# Build binary
make build

# Run tests
make test

# Run linter
make lint

# Format code
make fmt
```

### Database Schema

The application automatically creates these tables:

- `users` - User accounts
- `oauth_clients` - Registered client applications
- `device_codes` - Active device authorization requests
- `access_tokens` - Issued JWT tokens

### Extending the Server

**Add a new OAuth client:**

```go
client := &models.OAuthClient{
    Name:         "My App",
    ClientID:     uuid.New().String(),
    RedirectURIs: "http://localhost:3000/callback",
}
db.Create(client)
```

**Add custom scopes:**

Modify `services/device.go` to validate and store additional scopes.

---

## Security Considerations

### Production Deployment Checklist

- [ ] Change `JWT_SECRET` to a strong random value (32+ characters)
- [ ] Change `SESSION_SECRET` to a strong random value
- [ ] Use HTTPS (set `BASE_URL` to `https://...`)
- [ ] Change default user credentials
- [ ] Set appropriate `DeviceCodeExpiration` (default: 30 minutes)
- [ ] Set appropriate `JWTExpiration` (default: 1 hour)
- [ ] Configure firewall rules
- [ ] Enable rate limiting for token polling
- [ ] Regularly backup `oauth.db`

### Threat Model

**What AuthGate Protects Against:**

- ✅ Client secret exposure in distributed apps
- ✅ Phishing attacks (user authorizes on trusted domain)
- ✅ Replay attacks (device codes are single-use)
- ✅ Token tampering (JWT signature verification)

**What You Must Secure:**

- 🔒 Server host security
- 🔒 Database encryption at rest
- 🔒 TLS/HTTPS in production
- 🔒 Secret rotation policies

---

## Use Cases

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

---

## Comparison with Other Solutions

| Feature        | AuthGate | Auth0  | Keycloak | Custom OAuth |
| -------------- | -------- | ------ | -------- | ------------ |
| Device Flow    | ✅       | ✅     | ✅       | 🔧 DIY       |
| Self-Hosted    | ✅       | ❌     | ✅       | ✅           |
| Lightweight    | ✅       | N/A    | ❌       | 🔧 Varies    |
| Setup Time     | 5 min    | 15 min | 1 hour   | Days         |
| Learning Curve | Low      | Medium | High     | High         |
| Cost           | Free     | $$$    | Free     | Dev Time     |

---

## FAQ

**Q: Why not use OAuth password grant?**
A: Password grant requires users to enter credentials directly into your app, which trains users to trust third parties with passwords (security anti-pattern).

**Q: Can I use this in production?**
A: Yes, but ensure you follow the security checklist and harden the deployment. This is a reference implementation - audit it for your specific needs.

**Q: How do I add user registration?**
A: Implement registration handlers in `handlers/auth.go` and update the database schema.

**Q: Can I use this with multiple clients?**
A: Yes! Add additional clients to the `oauth_clients` table with unique `client_id` values.

**Q: What about token refresh?**
A: This implementation uses short-lived JWTs without refresh tokens. Implement refresh tokens by extending `models.AccessToken` and adding a `/oauth/token` refresh grant type.

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
