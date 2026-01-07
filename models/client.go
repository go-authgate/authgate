package models

import (
	"time"
)

type OAuthClient struct {
	ClientID   string `gorm:"primaryKey"`
	ClientName string `gorm:"not null"`
	Scopes     string `gorm:"not null"` // space-separated scopes
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TableName overrides the table name used by OAuthClient to `oauth_client`
func (OAuthClient) TableName() string {
	return "oauth_client"
}
