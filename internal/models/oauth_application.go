package models

import (
	"context"
	"database/sql/driver"
	"encoding/base32"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/util"

	"golang.org/x/crypto/bcrypt"
)

// ClientStatus represents the approval lifecycle of an OAuth client.
type ClientStatus = string

const (
	ClientStatusPending  ClientStatus = "pending"  // Awaiting admin approval
	ClientStatusActive   ClientStatus = "active"   // Admin approved / admin-created
	ClientStatusInactive ClientStatus = "inactive" // Admin rejected or disabled
)

// TokenProfile selects a named preset of access/refresh token lifetimes for a client.
// The effective TTLs are resolved at token issuance via config.TokenProfiles.
const (
	TokenProfileShort    = "short"
	TokenProfileStandard = "standard"
	TokenProfileLong     = "long"
)

// IsValidTokenProfile reports whether v is a recognised token profile name.
func IsValidTokenProfile(v string) bool {
	switch v {
	case TokenProfileShort, TokenProfileStandard, TokenProfileLong:
		return true
	}
	return false
}

// ResolveTokenProfile normalizes a stored or form-submitted profile name:
// surrounding whitespace is trimmed (common from form posts and API clients),
// empty input becomes "standard" (the rule for pre-migration rows and older
// callers). Unknown values pass through unchanged so callers can distinguish
// legitimate defaults from bad data.
func ResolveTokenProfile(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return TokenProfileStandard
	}
	return trimmed
}

// Base32 characters, but lowercased.
const lowerBase32Chars = "abcdefghijklmnopqrstuvwxyz234567"

// base32 encoder that uses lowered characters without padding.
var base32Lower = base32.NewEncoding(lowerBase32Chars).WithPadding(base32.NoPadding)

type OAuthApplication struct {
	ID                          int64       `gorm:"primaryKey;autoIncrement"`
	ClientID                    string      `gorm:"uniqueIndex;not null"`
	ClientSecret                string      `gorm:"not null"` // bcrypt hashed secret
	ClientName                  string      `gorm:"not null"`
	Description                 string      `gorm:"type:text"`
	UserID                      string      `gorm:"not null"`
	Scopes                      string      `gorm:"not null"`
	GrantTypes                  string      `gorm:"not null;default:'device_code'"`
	RedirectURIs                StringArray `gorm:"type:json"`
	ClientType                  string      `gorm:"not null;default:'public'"` // "confidential" or "public"
	EnableDeviceFlow            bool        `gorm:"not null;default:true"`
	EnableAuthCodeFlow          bool        `gorm:"not null;default:false"`
	EnableClientCredentialsFlow bool        `gorm:"not null;default:false"`              // Client Credentials Grant (RFC 6749 §4.4); confidential clients only
	Status                      string      `gorm:"not null;default:'active'"`           // ClientStatusPending / ClientStatusActive / ClientStatusInactive
	TokenProfile                string      `gorm:"not null;default:'standard';size:20"` // "short" / "standard" / "long"; resolves to a TTL preset in config
	Project                     string      `gorm:"size:64"`                             // Optional project identifier injected as JWT "project" claim. Format: ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}[a-zA-Z0-9]$ (validated in services).
	ServiceAccount              string      `gorm:"size:255"`                            // Optional service account identifier injected as JWT "service_account" claim.
	CreatedBy                   string
	CreatedAt                   time.Time
	UpdatedAt                   time.Time
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
func (s *StringArray) Scan(value any) error {
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
	return strings.Join(s, sep)
}

// TableName overrides the table name used by OAuthApplication to `oauth_applications`
func (OAuthApplication) TableName() string {
	return "oauth_applications"
}

// IsActive returns true when the client's status is active and can be used for OAuth flows.
func (app *OAuthApplication) IsActive() bool {
	return app.Status == ClientStatusActive
}
