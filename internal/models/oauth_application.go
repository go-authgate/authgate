package models

import (
	"context"
	"database/sql/driver"
	"encoding/base32"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-authgate/authgate/internal/util"

	"golang.org/x/crypto/bcrypt"
)

// Base32 characters, but lowercased.
const lowerBase32Chars = "abcdefghijklmnopqrstuvwxyz234567"

// base32 encoder that uses lowered characters without padding.
var base32Lower = base32.NewEncoding(lowerBase32Chars).WithPadding(base32.NoPadding)

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

// GenerateClientSecret will generate the client secret and returns the plaintext and saves the hash at the database
func (app *OAuthApplication) GenerateClientSecret(ctx context.Context) (string, error) {
	rBytes, err := util.CryptoRandomBytes(32)
	if err != nil {
		return "", err
	}
	// Add a prefix to the base32, this is in order to make it easier
	// for code scanners to grab sensitive tokens.
	clientSecret := "ago_" + base32Lower.EncodeToString(rBytes)

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	app.ClientSecret = string(hashedSecret)
	return clientSecret, nil
}

// ValidateClientSecret validates the given secret by the hash saved in database
func (app *OAuthApplication) ValidateClientSecret(secret []byte) bool {
	return bcrypt.CompareHashAndPassword([]byte(app.ClientSecret), secret) == nil
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
