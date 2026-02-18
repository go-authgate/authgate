package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

type OAuthApplication struct {
	ID                 int64       `gorm:"primaryKey;autoIncrement"`
	ClientID           string      `gorm:"uniqueIndex;not null"`
	ClientSecret       string      `gorm:"not null"` // bcrypt hashed secret
	ClientName         string      `gorm:"not null"`
	Description        string      `gorm:"type:text"`
	UserID             string      `gorm:"not null"`
	Scopes             string      `gorm:"not null"`
	GrantTypes         string      `gorm:"not null;default:'device_code'"`
	RedirectURIs       StringArray `gorm:"type:json"`
	ClientType         string      `gorm:"not null;default:'confidential'"` // "confidential" or "public"
	EnableDeviceFlow   bool        `gorm:"not null;default:true"`
	EnableAuthCodeFlow bool        `gorm:"not null;default:false"`
	IsActive           bool        `gorm:"not null;default:true"`
	CreatedBy          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// StringArray is a custom type for []string that can be stored as JSON in database
type StringArray []string

// Scan implements sql.Scanner interface
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to unmarshal JSON value")
	}
	return json.Unmarshal(bytes, s)
}

// Value implements driver.Valuer interface
func (s StringArray) Value() (driver.Value, error) {
	if len(s) == 0 {
		return json.Marshal([]string{})
	}
	return json.Marshal(s)
}

// Join returns a string with elements joined by the specified separator
func (s StringArray) Join(sep string) string {
	if len(s) == 0 {
		return ""
	}
	result := ""
	for i, str := range s {
		if i > 0 {
			result += sep
		}
		result += str
	}
	return result
}

// TableName overrides the table name used by OAuthApplication to `oauth_applications`
func (OAuthApplication) TableName() string {
	return "oauth_applications"
}
