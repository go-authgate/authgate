package models

import (
	"time"
)

type OAuthClient struct {
	ClientID     string `gorm:"primaryKey"`
	ClientSecret string `gorm:"not null"` // bcrypt hashed secret
	ClientName   string `gorm:"not null"`
	Description  string `gorm:"type:text"`
	Scopes       string `gorm:"not null"`                       // space-separated scopes
	GrantTypes   string `gorm:"not null;default:'device_code'"` // comma-separated grant types
	RedirectURIs string `gorm:"type:text"`                      // comma-separated redirect URIs
	IsActive     bool   `gorm:"not null;default:true"`
	CreatedBy    string // User ID who created this client
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TableName overrides the table name used by OAuthClient to `oauth_client`
func (OAuthClient) TableName() string {
	return "oauth_client"
}
