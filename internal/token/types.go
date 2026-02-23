package token

import "time"

// Token type constants
const (
	TokenTypeBearer = "Bearer"
)

// Result represents the result of token generation
type Result struct {
	TokenString string         // The JWT string
	TokenType   string         // "Bearer"
	ExpiresAt   time.Time      // Token expiration time
	Claims      map[string]any // Additional claims from provider
	Success     bool           // Generation success status
}

// ValidationResult represents the result of token verification
type ValidationResult struct {
	Valid     bool
	UserID    string
	ClientID  string
	Scopes    string
	ExpiresAt time.Time
	Claims    map[string]any
}

// RefreshResult represents the result of a refresh token operation
type RefreshResult struct {
	AccessToken  *Result // New access token (required)
	RefreshToken *Result // New refresh token (only present in rotation mode)
	Success      bool    // Operation success status
}
