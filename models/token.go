package models

import (
	"time"
)

type AccessToken struct {
	ID        string `gorm:"primaryKey"`
	Token     string `gorm:"uniqueIndex;not null"`
	TokenType string `gorm:"not null;default:'Bearer'"`
	UserID    string `gorm:"not null;index"`
	ClientID  string `gorm:"not null;index"`
	Scopes    string `gorm:"not null"` // space-separated scopes
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (t *AccessToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}
