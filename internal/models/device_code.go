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
	// Resource holds RFC 8707 Resource Indicator values requested at
	// /oauth/device/code and approved by the user at /device/verify. The
	// /oauth/token device-code grant rejects any token-time `resource` that
	// is not a subset of this set, so a polling client cannot widen the
	// audience after the user has authorized the device code.
	Resource     StringArray `gorm:"type:json"`
	ExpiresAt    time.Time   `gorm:"index"`
	Interval     int         // polling interval in seconds
	UserID       string      // filled after authorization
	Authorized   bool        `gorm:"default:false"`
	AuthorizedAt time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (d *DeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}
