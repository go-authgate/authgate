package models

import (
	"time"
)

// User role constants
const (
	UserRoleAdmin = "admin"
	UserRoleUser  = "user"
)

// AuthSource constants define where a user authenticates from.
const (
	AuthSourceLocal   = "local"
	AuthSourceHTTPAPI = "http_api"
)

type User struct {
	ID            string `gorm:"primaryKey"`
	Username      string `gorm:"uniqueIndex;not null"`
	Email         string `gorm:"uniqueIndex;not null"` // Email is unique and required
	PasswordHash  string // OAuth-only users have empty password
	Role          string `gorm:"not null;default:'user'"` // "admin" or "user"
	FullName      string // User full name
	AvatarURL     string // User avatar URL (from OAuth or manual)
	IsActive      bool   `gorm:"not null;default:true"`  // false = disabled by admin
	EmailVerified bool   `gorm:"not null;default:false"` // true when a trusted OAuth provider has verified the email

	// External authentication support
	ExternalID string `gorm:"index"`           // External user ID (e.g., from HTTP API)
	AuthSource string `gorm:"default:'local'"` // "local" or "http_api"

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsAdmin returns true if the user has admin role
func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
}

// IsExternal returns true if user authenticates via external provider
func (u *User) IsExternal() bool {
	return u.AuthSource != AuthSourceLocal && u.AuthSource != ""
}
