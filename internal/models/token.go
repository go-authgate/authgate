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
	Status        string    `gorm:"not null;default:'active';index:idx_token_client_status,priority:2;index:idx_token_family_status,priority:2;index:idx_token_auth_status,priority:2;index:idx_token_cat_status_exp,priority:2"`
	UserID        string    `gorm:"not null;index"`
	ClientID      string    `gorm:"not null;index:idx_token_client_status,priority:1"`
	Scopes        string    `gorm:"not null"` // space-separated scopes
	ExpiresAt     time.Time `gorm:"index;index:idx_token_cat_status_exp,priority:3"`
	CreatedAt     time.Time
	LastUsedAt    *time.Time `gorm:"index"`                                                        // Last time token was used (for refresh tokens)
	ParentTokenID string     `gorm:"index"`                                                        // Links access tokens to their refresh token
	TokenFamilyID string     `gorm:"index:idx_token_family_status,priority:1;default:'';not null"` // Stable root ID for rotation replay detection
	// AuthorizationID is the FK → UserAuthorization.ID. Set for both
	// authorization-code and device-code grants when a UserAuthorization
	// exists at issuance time, so /account/authorizations and the admin
	// "revoke all users for this client" action cascade-revoke them. Nil
	// for client_credentials (no user) and for device-code tokens issued
	// against an older authorization that pre-dates consent persistence.
	AuthorizationID *uint `gorm:"index:idx_token_auth_status,priority:1"`
	// Resource semantics differ by TokenCategory:
	//
	//   - Access tokens: this is the audience SNAPSHOT taken at issuance —
	//     exactly what the JWT was signed with, whether from a per-request
	//     RFC 8707 resource binding or the static JWTAudience config that
	//     the provider fell back to when no resource was supplied. RFC 7662
	//     introspection reads this snapshot directly so operators rotating
	//     JWT_AUDIENCE while older tokens are still active won't change
	//     what introspection reports for those tokens. Empty means the JWT
	//     was issued without an `aud` claim.
	//   - Refresh tokens: this is the ORIGINAL /authorize-time (or
	//     /oauth/device/code) grant's RFC 8707 resource set, persisted
	//     purely so the refresh grant can enforce RFC 8707 §2.2 subset
	//     rules on subsequent refresh requests. The refresh JWT's own `aud`
	//     is signed with nil audience override and falls back to the static
	//     JWTAudience config — refresh.Resource is NOT the refresh JWT's
	//     audience and must not be advertised as such (RFC 7662
	//     introspection omits `aud` for refresh tokens entirely; see
	//     introspectAudience).
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
