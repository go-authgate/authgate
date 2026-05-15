package models

import (
	"time"
)

// TokenStatus represents the lifecycle state of an access or refresh token.
type TokenStatus = string

const (
	TokenStatusActive   TokenStatus = "active"
	TokenStatusDisabled TokenStatus = "disabled"
	TokenStatusRevoked  TokenStatus = "revoked"
)

// TokenCategory distinguishes access tokens from refresh tokens.
type TokenCategory = string

const (
	TokenCategoryAccess  TokenCategory = "access"
	TokenCategoryRefresh TokenCategory = "refresh"
)

type AccessToken struct {
	ID        string `gorm:"primaryKey"`
	TokenHash string `gorm:"uniqueIndex;not null"`
	RawToken  string `gorm:"-"` // In-memory only; never persisted to DB
	TokenType string `gorm:"not null;default:'Bearer'"`
	// 'access' or 'refresh'
	TokenCategory string `gorm:"not null;default:'access';index:idx_token_cat_status_exp,priority:1"`
	// 'active', 'disabled', 'revoked'
	Status          string    `gorm:"not null;default:'active';index:idx_token_client_status,priority:2;index:idx_token_family_status,priority:2;index:idx_token_auth_status,priority:2;index:idx_token_cat_status_exp,priority:2"`
	UserID          string    `gorm:"not null;index"`
	ClientID        string    `gorm:"not null;index:idx_token_client_status,priority:1"`
	Scopes          string    `gorm:"not null"` // space-separated scopes
	ExpiresAt       time.Time `gorm:"index;index:idx_token_cat_status_exp,priority:3"`
	CreatedAt       time.Time
	LastUsedAt      *time.Time `gorm:"index"`                                                        // Last time token was used (for refresh tokens)
	ParentTokenID   string     `gorm:"index"`                                                        // Links access tokens to their refresh token
	TokenFamilyID   string     `gorm:"index:idx_token_family_status,priority:1;default:'';not null"` // Stable root ID for rotation replay detection
	AuthorizationID *uint      `gorm:"index:idx_token_auth_status,priority:1"`                       // FK → UserAuthorization.ID (nil for device_code grants)
	// RFC 8707 Resource Indicators bound to this token row. Semantics differ
	// by TokenCategory:
	//
	//   - Access tokens: this IS the JWT `aud` claim (collapsed to string for
	//     a single value, slice for multiple, omitted when empty so the JWT
	//     falls back to the static JWTAudience config).
	//   - Refresh tokens: this is the ORIGINAL grant's resource set,
	//     persisted purely so the refresh grant can enforce RFC 8707 §2.2
	//     subset rules on subsequent refresh requests. The refresh JWT's own
	//     `aud` is signed with nil audience override and falls back to the
	//     static JWTAudience config — refresh.Resource is NOT the refresh
	//     JWT's audience and must not be advertised as such (e.g. RFC 7662
	//     introspection omits `aud` for refresh tokens entirely).
	Resource StringArray `gorm:"type:json"`
}

func (t *AccessToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

func (t *AccessToken) IsActive() bool {
	return t.Status == TokenStatusActive
}

func (t *AccessToken) IsRevoked() bool {
	return t.Status == TokenStatusRevoked
}

func (t *AccessToken) IsDisabled() bool {
	return t.Status == TokenStatusDisabled
}

func (t *AccessToken) IsAccessToken() bool {
	return t.TokenCategory == TokenCategoryAccess
}

func (t *AccessToken) IsRefreshToken() bool {
	return t.TokenCategory == TokenCategoryRefresh
}
