package models

import (
	"time"
)

type DeviceCode struct {
	DeviceCode   string `gorm:"primaryKey"`
	UserCode     string `gorm:"uniqueIndex;not null"`
	ClientID     string `gorm:"not null;index"`
	Scopes       string `gorm:"not null"` // space-separated scopes
	ExpiresAt    time.Time
	Interval     int    // polling interval in seconds
	UserID       string // filled after authorization
	Authorized   bool   `gorm:"default:false"`
	AuthorizedAt time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (d *DeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}
