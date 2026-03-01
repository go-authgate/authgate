package core

import (
	"context"
	"time"
)

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
