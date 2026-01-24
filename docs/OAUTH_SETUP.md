# OAuth Setup Guide

This guide explains how to integrate GitHub and Gitea OAuth authentication with AuthGate.

## Features

- **Multiple OAuth Providers**: Support for GitHub, Gitea, and extensible to other providers
- **Email-based Account Linking**: Automatically links OAuth accounts to existing users with the same email
- **Auto-registration**: New users can be automatically created via OAuth (controlled by `OAUTH_AUTO_REGISTER` config)
- **Multiple Authentication Methods**: Users can have both password and OAuth authentication
- **Profile Sync**: Avatar and profile information synced from OAuth providers

## Architecture

### User Model

```go
type User struct {
    ID           string
    Username     string // Unique
    Email        string // Unique and required
    PasswordHash string // Empty for OAuth-only users
    AvatarURL    string // Synced from OAuth
    // ...
}
```

### OAuth Connection Model

```go
type OAuthConnection struct {
    ID             string
    UserID         string
    Provider       string // "github", "gitea"
    ProviderUserID string // Provider's user ID
    AccessToken    string // OAuth access token
    // ...
}
```

### Authentication Flow

1. **Existing OAuth Connection**: User clicks "Sign in with GitHub" → Already linked → Login immediately
2. **Existing User (same email)**: OAuth email matches existing user → Automatically link and login
3. **New User**: No existing user or connection → Create new user account (if `OAUTH_AUTO_REGISTER=true`), otherwise show error

## GitHub OAuth Setup

### 1. Create GitHub OAuth App

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: AuthGate
   - **Homepage URL**: `http://localhost:8080` (for development)
   - **Authorization callback URL**: `http://localhost:8080/auth/callback/github`
4. Click "Register application"
5. Copy the **Client ID** and generate a **Client Secret**

### 2. Configure AuthGate

Add to `.env`:

```bash
# GitHub OAuth
GITHUB_OAUTH_ENABLED=true
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_REDIRECT_URL=http://localhost:8080/auth/callback/github
GITHUB_SCOPES=user:email
```

### 3. Test

1. Start AuthGate: `./bin/authgate server`
2. Visit `http://localhost:8080/login`
3. Click "Sign in with GitHub"
4. Authorize the application
5. You'll be logged in and redirected to `/device`

## Gitea OAuth Setup

### 1. Create Gitea OAuth Application

1. Log in to your Gitea instance
2. Go to Settings → Applications → Manage OAuth2 Applications
3. Click "Create a new OAuth2 Application"
4. Fill in:
   - **Application Name**: AuthGate
   - **Redirect URI**: `http://localhost:8080/auth/callback/gitea`
5. Click "Create Application"
6. Copy the **Client ID** and **Client Secret**

### 2. Configure AuthGate

Add to `.env`:

```bash
# Gitea OAuth
GITEA_OAUTH_ENABLED=true
GITEA_URL=https://gitea.example.com
GITEA_CLIENT_ID=your_client_id_here
GITEA_CLIENT_SECRET=your_client_secret_here
GITEA_REDIRECT_URL=http://localhost:8080/auth/callback/gitea
GITEA_SCOPES=read:user
```

### 3. Test

1. Start AuthGate: `./bin/authgate server`
2. Visit `http://localhost:8080/login`
3. Click "Sign in with Gitea"
4. Authorize the application
5. You'll be logged in and redirected to `/device`

## Production Deployment

### HTTPS Configuration

For production, use HTTPS URLs:

```bash
# Production URLs
BASE_URL=https://auth.example.com
GITHUB_REDIRECT_URL=https://auth.example.com/auth/callback/github
GITEA_REDIRECT_URL=https://auth.example.com/auth/callback/gitea
```

Update your OAuth app settings in GitHub/Gitea to use the production callback URLs.

### Security Considerations

1. **HTTPS Required**: Always use HTTPS in production
2. **Secure Secrets**: Use environment variables or secret management for credentials
3. **Email Validation**: OAuth providers return email addresses that are used for account linking
4. **Token Storage**: OAuth tokens are stored in the database (consider encryption at rest)
5. **TLS Verification**: Never set `OAUTH_INSECURE_SKIP_VERIFY=true` in production - only use for development with self-signed certificates

## User Scenarios

### Scenario 1: New User Signs Up via GitHub

```txt
1. User clicks "Sign in with GitHub"
2. GitHub callback: email=alice@example.com, username=alice
3. System checks:
   - No OAuth connection exists
   - No user with email=alice@example.com exists
4. System creates:
   - New user: username=alice, email=alice@example.com, password=""
   - OAuth connection: provider=github, provider_user_id=12345
5. User is logged in
```

### Scenario 2: Existing User Links GitHub Account

```txt
1. User Bob already exists:
   - username: bob
   - email: bob@example.com
   - password: (set)
2. Bob clicks "Sign in with GitHub"
3. GitHub callback: email=bob@example.com
4. System checks:
   - No OAuth connection exists
   - User with email=bob@example.com exists ✓
5. System creates:
   - OAuth connection linking Bob's account to GitHub
6. Bob is logged in

Bob can now login with:
  - Username/password (existing method)
  - GitHub OAuth (newly added)
```

### Scenario 3: User Has Multiple OAuth Accounts

```txt
Alice can have:
  - Local auth: alice / password123
  - GitHub: alice-github (linked)
  - Gitea: alice-work (linked)

All three methods log into the same AuthGate account.
```

## Troubleshooting

### "OAuth provider has no email address"

**Problem**: OAuth provider doesn't return an email address.

**Solution**:

- GitHub: Make sure your email is public or grant `user:email` scope
- Gitea: Check that your Gitea account has an email address

### "Username already exists"

**Problem**: OAuth username conflicts with existing local user.

**Solution**: System automatically appends provider name or number suffix:

- `alice` → `alice-github`
- `alice-github` → `alice-github-1`

### "OAuth session expired"

**Problem**: Browser session expired during OAuth flow.

**Solution**: Clear cookies and try again.

### Self-signed Certificate Errors (Development)

**Problem**: OAuth fails with TLS certificate verification errors when using self-signed certificates.

**Solution**: For development/testing environments only:

```bash
# .env
OAUTH_INSECURE_SKIP_VERIFY=true
```

**⚠️ WARNING**: Never use this in production! It disables TLS verification and makes your application vulnerable to man-in-the-middle attacks.

## API Endpoints

OAuth authentication adds these endpoints:

- `GET /auth/login/:provider` - Initiates OAuth flow (provider: github, gitea)
- `GET /auth/callback/:provider` - OAuth callback endpoint

## Environment Variables Reference

| Variable                     | Required   | Default      | Description                              |
| ---------------------------- | ---------- | ------------ | ---------------------------------------- |
| `GITHUB_OAUTH_ENABLED`       | No         | `false`      | Enable GitHub OAuth                      |
| `GITHUB_CLIENT_ID`           | If enabled | -            | GitHub OAuth Client ID                   |
| `GITHUB_CLIENT_SECRET`       | If enabled | -            | GitHub OAuth Client Secret               |
| `GITHUB_REDIRECT_URL`        | If enabled | -            | GitHub OAuth callback URL                |
| `GITHUB_SCOPES`              | No         | `user:email` | GitHub OAuth scopes                      |
| `GITEA_OAUTH_ENABLED`        | No         | `false`      | Enable Gitea OAuth                       |
| `GITEA_URL`                  | If enabled | -            | Gitea instance URL                       |
| `GITEA_CLIENT_ID`            | If enabled | -            | Gitea OAuth Client ID                    |
| `GITEA_CLIENT_SECRET`        | If enabled | -            | Gitea OAuth Client Secret                |
| `GITEA_REDIRECT_URL`         | If enabled | -            | Gitea OAuth callback URL                 |
| `GITEA_SCOPES`               | No         | `read:user`  | Gitea OAuth scopes                       |
| `OAUTH_AUTO_REGISTER`        | No         | `true`       | Allow auto-creation of accounts          |
| `OAUTH_TIMEOUT`              | No         | `15s`        | HTTP client timeout for OAuth requests   |
| `OAUTH_INSECURE_SKIP_VERIFY` | No         | `false`      | Skip TLS verification (dev/testing only) |

**Note on Auto-Registration**: When `OAUTH_AUTO_REGISTER=false`, only users with existing accounts (matched by email) can login via OAuth. New users attempting to login will see an error message asking them to contact the administrator. This is useful for organizations that want to restrict OAuth access to pre-approved users only.

## Adding More OAuth Providers

To add a new OAuth provider (e.g., GitLab):

1. **Add provider in `internal/auth/oauth_provider.go`**:

```go
func NewGitLabProvider(cfg OAuthProviderConfig) *OAuthProvider {
    return &OAuthProvider{
        provider: "gitlab",
        config: &oauth2.Config{
            ClientID:     cfg.ClientID,
            ClientSecret: cfg.ClientSecret,
            RedirectURL:  cfg.RedirectURL,
            Scopes:       cfg.Scopes,
            Endpoint:     gitlab.Endpoint,
        },
    }
}
```

2. **Add config in `internal/config/config.go`**:

```go
GitLabOAuthEnabled bool
GitLabClientID     string
// ...
```

3. **Initialize in `main.go`**:

```go
if cfg.GitLabOAuthEnabled {
    providers["gitlab"] = auth.NewGitLabProvider(...)
}
```

4. **Update login template** to add GitLab button

## Database Schema

### oauth_connections Table

```sql
CREATE TABLE oauth_connections (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_username TEXT,
    provider_email TEXT,
    avatar_url TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_expiry TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    UNIQUE(provider, provider_user_id),
    UNIQUE(user_id, provider),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

### Indexes

- `(provider, provider_user_id)` - Unique, for OAuth provider lookup
- `(user_id, provider)` - Unique, ensures one connection per provider per user
- `user_id` - For querying all connections for a user
