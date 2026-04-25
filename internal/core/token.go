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
type IDTokenProvider interface {
	GenerateIDToken(params IDTokenParams) (string, error)
}

// TokenResult is the outcome of a token generation call.
type TokenResult struct {
	TokenString string
	TokenType   string
	ExpiresAt   time.Time
	Claims      map[string]any
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
}

// TokenProvider is the interface that token-generation backends must implement.
// A ttl of 0 on any Generate* method means "use the provider's default expiry"
// (typically derived from config). A non-zero ttl overrides the default and
// disables any jitter the provider would normally apply.
//
// extraClaims (when non-empty) is merged into the generated JWT after standard
// claims are set; standard claims (iss, sub, exp, iat, jti, aud, type, scope,
// user_id, client_id) take precedence and cannot be overridden.
type TokenProvider interface {
	GenerateToken(
		ctx context.Context,
		userID, clientID, scopes string,
		ttl time.Duration,
		extraClaims map[string]any,
	) (*TokenResult, error)
	GenerateRefreshToken(
		ctx context.Context,
		userID, clientID, scopes string,
		ttl time.Duration,
		extraClaims map[string]any,
	) (*TokenResult, error)
	// GenerateClientCredentialsToken generates a token for the client_credentials grant.
	// May apply a different expiry or claim set than GenerateToken.
	GenerateClientCredentialsToken(
		ctx context.Context,
		userID, clientID, scopes string,
		ttl time.Duration,
		extraClaims map[string]any,
	) (*TokenResult, error)
	ValidateToken(ctx context.Context, tokenString string) (*TokenValidationResult, error)
	RefreshAccessToken(
		ctx context.Context,
		refreshToken string,
		accessTTL, refreshTTL time.Duration,
		extraClaims map[string]any,
	) (*TokenRefreshResult, error)
	Name() string
}
