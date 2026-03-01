package core

import (
	"context"
	"time"
)

// IDTokenParams holds all data needed to generate an OIDC ID Token (OIDC Core 1.0 §2).
type IDTokenParams struct {
	Issuer   string
	Subject  string // UserID
	Audience string // ClientID
	AuthTime time.Time
	Nonce    string
	Expiry   time.Duration
	AtHash   string // base64url(SHA-256(access_token)[:16]) – optional

	// Scope-gated profile claims (include when "profile" scope was granted)
	Name              string
	PreferredUsername string
	Picture           string
	UpdatedAt         *time.Time

	// Scope-gated email claims (include when "email" scope was granted)
	Email         string
	EmailVerified bool
}

// IDTokenProvider is an optional capability of a TokenProvider.
// Only LocalTokenProvider implements it; HTTP API providers cannot produce OIDC ID tokens.
type IDTokenProvider interface {
	GenerateIDToken(params IDTokenParams) (string, error)
}

// TokenResult is the outcome of a token generation call.
type TokenResult struct {
	TokenString string
	TokenType   string
	ExpiresAt   time.Time
	Claims      map[string]any
	Success     bool
}

// TokenValidationResult is the outcome of a token validation call.
type TokenValidationResult struct {
	Valid     bool
	UserID    string
	ClientID  string
	Scopes    string
	ExpiresAt time.Time
	Claims    map[string]any
}

// TokenRefreshResult is the outcome of a refresh-token exchange.
type TokenRefreshResult struct {
	AccessToken  *TokenResult // required
	RefreshToken *TokenResult // non-nil only in rotation mode
	Success      bool
}

// TokenProvider is the interface that token-generation backends must implement.
// Both LocalTokenProvider and HTTPTokenProvider satisfy this interface.
type TokenProvider interface {
	GenerateToken(ctx context.Context, userID, clientID, scopes string) (*TokenResult, error)
	GenerateRefreshToken(ctx context.Context, userID, clientID, scopes string) (*TokenResult, error)
	// GenerateClientCredentialsToken generates a token for the client_credentials grant.
	// HTTP API provider delegates to GenerateToken; local provider may apply
	// a different expiry or claim set.
	GenerateClientCredentialsToken(
		ctx context.Context,
		userID, clientID, scopes string,
	) (*TokenResult, error)
	ValidateToken(ctx context.Context, tokenString string) (*TokenValidationResult, error)
	RefreshAccessToken(
		ctx context.Context,
		refreshToken string,
		enableRotation bool,
	) (*TokenRefreshResult, error)
	Name() string
}
