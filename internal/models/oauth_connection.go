package models

import (
	"time"
)

// OAuthConnection represents an OAuth provider connection for a user
type OAuthConnection struct {
	ID             string `gorm:"primaryKey"`
	UserID         string `gorm:"not null;uniqueIndex:idx_oauth_user_provider,priority:1"`
	Provider       string `gorm:"not null;uniqueIndex:idx_oauth_provider_user,priority:1;uniqueIndex:idx_oauth_user_provider,priority:2"` // "github", "gitea", "gitlab"
	ProviderUserID string `gorm:"not null;uniqueIndex:idx_oauth_provider_user,priority:2"`                                                // Provider's user ID

	// OAuth metadata (snapshot for audit/reference)
	ProviderUsername string // Provider's username
	ProviderEmail    string // Provider's email (snapshot)
	AvatarURL        string // User avatar URL from provider

	// Token storage (should be encrypted in production)
	AccessToken  string    `gorm:"type:text"` // OAuth access token
	RefreshToken string    `gorm:"type:text"` // OAuth refresh token
	TokenExpiry  time.Time // Token expiration time

	// Activity tracking
	LastUsedAt time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName overrides the table name used by OAuthClient to `oauth_client`
func (OAuthConnection) TableName() string {
	return "oauth_connections"
}
