package models

import (
	"time"
)

type AccessToken struct {
	ID              string `gorm:"primaryKey"`
	TokenHash       string `gorm:"uniqueIndex;not null"`
	RawToken        string `gorm:"-"` // In-memory only; never persisted to DB
	TokenType       string `gorm:"not null;default:'Bearer'"`
	TokenCategory   string `gorm:"not null;default:'access';index"` // 'access' or 'refresh'
	Status          string `gorm:"not null;default:'active';index"` // 'active', 'disabled', 'revoked'
	UserID          string `gorm:"not null;index"`
	ClientID        string `gorm:"not null;index"`
	Scopes          string `gorm:"not null"` // space-separated scopes
	ExpiresAt       time.Time
	CreatedAt       time.Time
	LastUsedAt      *time.Time `gorm:"index"` // Last time token was used (for refresh tokens)
	ParentTokenID   string     `gorm:"index"` // Links access tokens to their refresh token
	AuthorizationID *uint      `gorm:"index"` // FK → UserAuthorization.ID (nil for device_code grants)
}

func (t *AccessToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsActive returns true if token status is 'active'
func (t *AccessToken) IsActive() bool {
	return t.Status == "active"
}

// IsRevoked returns true if token status is 'revoked'
func (t *AccessToken) IsRevoked() bool {
	return t.Status == "revoked"
}

// IsDisabled returns true if token status is 'disabled'
func (t *AccessToken) IsDisabled() bool {
	return t.Status == "disabled"
}

// IsAccessToken returns true if token category is 'access'
func (t *AccessToken) IsAccessToken() bool {
	return t.TokenCategory == "access"
}

// IsRefreshToken returns true if token category is 'refresh'
func (t *AccessToken) IsRefreshToken() bool {
	return t.TokenCategory == "refresh"
}
