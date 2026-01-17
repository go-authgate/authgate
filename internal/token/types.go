package token

import "time"

// Token type constants
const (
	TokenTypeBearer = "Bearer"
)

// TokenResult represents the result of token generation
type TokenResult struct {
	TokenString string         // The JWT string
	TokenType   string         // "Bearer"
	ExpiresAt   time.Time      // Token expiration time
	Claims      map[string]any // Additional claims from provider
	Success     bool           // Generation success status
}

// TokenValidationResult represents the result of token verification
type TokenValidationResult struct {
	Valid     bool
	UserID    string
	ClientID  string
	Scopes    string
	ExpiresAt time.Time
	Claims    map[string]any
}

// RefreshResult represents the result of a refresh token operation
type RefreshResult struct {
	AccessToken  *TokenResult // New access token (required)
	RefreshToken *TokenResult // New refresh token (only present in rotation mode)
	Success      bool         // Operation success status
}
