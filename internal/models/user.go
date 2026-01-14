package models

import (
	"time"
)

type User struct {
	ID           string `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	Role         string `gorm:"not null;default:'user'"` // "admin" or "user"

	// External authentication support
	ExternalID string `gorm:"index"`           // External user ID (e.g., from HTTP API)
	AuthSource string `gorm:"default:'local'"` // "local" or "http_api"
	Email      string // User email (optional)
	FullName   string // User full name (optional)

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsAdmin returns true if the user has admin role
func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

// IsExternal returns true if user authenticates via external provider
func (u *User) IsExternal() bool {
	return u.AuthSource != "local" && u.AuthSource != ""
}
