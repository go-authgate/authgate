package models

import (
	"time"
)

type DeviceCode struct {
	ID             int64  `gorm:"primaryKey;autoIncrement"`
	DeviceCode     string `gorm:"-"`                    // Not stored in DB, only for in-memory use
	DeviceCodeHash string `gorm:"uniqueIndex;not null"` // PBKDF2 hash of device code
	DeviceCodeSalt string `gorm:"not null"`             // Random salt for hashing
	DeviceCodeID   string `gorm:"index;not null"`       // Last 8 chars for quick lookup
	UserCode       string `gorm:"uniqueIndex;not null"`
	ClientID       string `gorm:"not null;index"`
	Scopes         string `gorm:"not null"` // space-separated scopes
	ExpiresAt      time.Time
	Interval       int    // polling interval in seconds
	UserID         string // filled after authorization
	Authorized     bool   `gorm:"default:false"`
	AuthorizedAt   time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (d *DeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}
