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
// extraClaims (when non-empty) is merged into the generated JWT before standard
// claims are set; standard claims (iss, sub, exp, iat, jti, aud, type, scope,
// user_id, client_id) take precedence and cannot be overridden.
//
// audience (when non-empty) overrides the "aud" claim with the supplied values
// (RFC 8707 Resource Indicators). When empty, the provider falls back to its
// default audience configuration. Caller-supplied "aud" inside extraClaims is
// always stripped — audience must be passed explicitly through this parameter.
type TokenProvider interface {
	GenerateToken(
		ctx context.Context,
		userID, clientID, scopes string,
		ttl time.Duration,
		extraClaims map[string]any,
		audience []string,
	) (*TokenResult, error)
	GenerateRefreshToken(
		ctx context.Context,
		userID, clientID, scopes string,
		ttl time.Duration,
		extraClaims map[string]any,
		audience []string,
	) (*TokenResult, error)
	// GenerateClientCredentialsToken generates a token for the client_credentials grant.
	// May apply a different expiry or claim set than GenerateToken.
	GenerateClientCredentialsToken(
		ctx context.Context,
		userID, clientID, scopes string,
		ttl time.Duration,
		extraClaims map[string]any,
		audience []string,
	) (*TokenResult, error)
	ValidateToken(ctx context.Context, tokenString string) (*TokenValidationResult, error)
	// ValidateRefreshToken verifies a refresh-token JWT and returns the parsed
	// claims (including `aud`). Callers — notably the refresh flow in
	// TokenService — use the signed claims as the authoritative source of the
	// original grant's audience when the persisted `Resource` column is
	// empty (e.g. legacy rows issued before fix #2 snapshotted the effective
	// audience on issuance). This prevents a later JWT_AUDIENCE rotation
	// from silently retargeting refreshed access tokens to an audience the
	// original token's JWT never carried.
	ValidateRefreshToken(
		ctx context.Context,
		tokenString string,
	) (*TokenValidationResult, error)
	// RefreshAccessToken issues a new access token (and, in rotation mode, a
	// new refresh token) from a valid refresh-token string.
	//
	// accessAudience and refreshAudience are kept separate so a refresh token
	// never carries the per-request resource-server `aud`. A refresh token is
	// presented to the AS, not the RS — emitting the same per-request audience
	// as the access token would let a downstream JWT validator that only
	// checks signature/iss/exp/aud silently accept the refresh token as if it
	// were an access token. Pass nil for refreshAudience to fall back to the
	// static JWTAudience config; deployments are expected to set
	// `JWT_AUDIENCE` to an AS-only value (or leave it unset so the claim is
	// omitted) — pointing it at a resource server would re-introduce the
	// confusion this split is designed to prevent.
	RefreshAccessToken(
		ctx context.Context,
		refreshToken string,
		accessTTL, refreshTTL time.Duration,
		extraClaims map[string]any,
		accessAudience []string,
		refreshAudience []string,
	) (*TokenRefreshResult, error)
	Name() string
}
