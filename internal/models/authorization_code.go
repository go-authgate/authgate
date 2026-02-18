package models

import "time"

// AuthorizationCode stores OAuth 2.0 authorization codes (RFC 6749).
// Codes are short-lived (default 10 minutes) and single-use.
type AuthorizationCode struct {
	ID   uint   `gorm:"primaryKey;autoIncrement"`
	UUID string `gorm:"uniqueIndex;size:36;not null"` // Public UUID for API/UI identification

	// Code storage: SHA256 hash for security, prefix for quick lookup
	CodeHash   string `gorm:"uniqueIndex;not null"`  // SHA256(plainCode)
	CodePrefix string `gorm:"index;not null;size:8"` // First 8 chars for quick lookup

	// Relations (int PK for fast JOIN, string ClientID for OAuth protocol)
	ApplicationID int64  `gorm:"not null;index"` // FK → OAuthApplication.ID
	ClientID      string `gorm:"not null;index"` // Denormalized ClientID UUID (OAuth protocol use)
	UserID        string `gorm:"not null;index"` // FK → User.ID

	RedirectURI string `gorm:"not null"`
	Scopes      string `gorm:"not null"`

	// PKCE (RFC 7636)
	CodeChallenge       string `gorm:"default:''"`     // code_challenge (empty = PKCE not used)
	CodeChallengeMethod string `gorm:"default:'S256'"` // "S256" or "plain"

	ExpiresAt time.Time
	UsedAt    *time.Time // Set immediately upon exchange; prevents replay attacks
	CreatedAt time.Time
}

func (a *AuthorizationCode) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

func (a *AuthorizationCode) IsUsed() bool {
	return a.UsedAt != nil
}

func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}
