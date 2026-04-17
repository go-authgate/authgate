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

// Token endpoint authentication methods (RFC 7591 §2).
const (
	TokenEndpointAuthNone              = "none"                // Public client, no authentication
	TokenEndpointAuthClientSecretBasic = "client_secret_basic" // HTTP Basic (default)
	TokenEndpointAuthClientSecretPost  = "client_secret_post"  // client_secret in form body
	TokenEndpointAuthPrivateKeyJWT     = "private_key_jwt"     // RFC 7523 JWT Bearer Assertion
)

// Client assertion signing algorithms supported for private_key_jwt.
const (
	AssertionAlgRS256 = "RS256"
	AssertionAlgES256 = "ES256"
)

// Base32 characters, but lowercased.
const lowerBase32Chars = "abcdefghijklmnopqrstuvwxyz234567"

// base32 encoder that uses lowered characters without padding.
var base32Lower = base32.NewEncoding(lowerBase32Chars).WithPadding(base32.NoPadding)

type OAuthApplication struct {
	ID                          int64       `gorm:"primaryKey;autoIncrement"`
	ClientID                    string      `gorm:"uniqueIndex;not null"`
	ClientSecret                string      `gorm:"not null;default:''"` // bcrypt hashed secret; empty for public / private_key_jwt clients
	ClientName                  string      `gorm:"not null"`
	Description                 string      `gorm:"type:text"`
	UserID                      string      `gorm:"not null"`
	Scopes                      string      `gorm:"not null"`
	GrantTypes                  string      `gorm:"not null;default:'device_code'"`
	RedirectURIs                StringArray `gorm:"type:json"`
	ClientType                  string      `gorm:"not null;default:'public'"` // "confidential" or "public"
	EnableDeviceFlow            bool        `gorm:"not null;default:true"`
	EnableAuthCodeFlow          bool        `gorm:"not null;default:false"`
	EnableClientCredentialsFlow bool        `gorm:"not null;default:false"`                 // Client Credentials Grant (RFC 6749 §4.4); confidential clients only
	Status                      string      `gorm:"not null;default:'active'"`              // ClientStatusPending / ClientStatusActive / ClientStatusInactive
	TokenEndpointAuthMethod     string      `gorm:"not null;default:'client_secret_basic'"` // RFC 7591 §2
	TokenEndpointAuthSigningAlg string      `gorm:"type:varchar(10);not null;default:''"`   // RS256 | ES256 (required for private_key_jwt)
	JWKSURI                     string      `gorm:"type:varchar(500);not null;default:''"`  // Remote JWKS endpoint URL (mutually exclusive with JWKS)
	JWKS                        string      `gorm:"type:text;not null;default:''"`          // Inline JWK Set JSON (mutually exclusive with JWKSURI)
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

// UsesPrivateKeyJWT reports whether the client authenticates using JWT Bearer
// Assertions (RFC 7523) at the token endpoint.
func (app *OAuthApplication) UsesPrivateKeyJWT() bool {
	return app.TokenEndpointAuthMethod == TokenEndpointAuthPrivateKeyJWT
}

// UsesClientSecret reports whether the client authenticates using a shared
// secret (either HTTP Basic or form-body). Public clients and private_key_jwt
// clients return false.
func (app *OAuthApplication) UsesClientSecret() bool {
	return app.TokenEndpointAuthMethod == TokenEndpointAuthClientSecretBasic ||
		app.TokenEndpointAuthMethod == TokenEndpointAuthClientSecretPost
}

// ValidateKeyMaterial verifies that a private_key_jwt client has exactly one of
// JWKSURI or JWKS set, and that the signing algorithm is supported. For other
// auth methods, it verifies no key material is present.
func (app *OAuthApplication) ValidateKeyMaterial() error {
	if !app.UsesPrivateKeyJWT() {
		if app.JWKSURI != "" || app.JWKS != "" || app.TokenEndpointAuthSigningAlg != "" {
			return errors.New(
				"JWKS, JWKS URI, and signing algorithm must be empty when token_endpoint_auth_method is not private_key_jwt",
			)
		}
		return nil
	}

	// private_key_jwt validation
	hasURI := strings.TrimSpace(app.JWKSURI) != ""
	hasInline := strings.TrimSpace(app.JWKS) != ""
	if !hasURI && !hasInline {
		return errors.New("private_key_jwt requires either jwks_uri or jwks to be provided")
	}
	if hasURI && hasInline {
		return errors.New("private_key_jwt requires jwks_uri and jwks to be mutually exclusive")
	}

	switch app.TokenEndpointAuthSigningAlg {
	case AssertionAlgRS256, AssertionAlgES256:
		return nil
	case "":
		return errors.New(
			"private_key_jwt requires token_endpoint_auth_signing_alg to be set (RS256 or ES256)",
		)
	default:
		return errors.New(
			"unsupported token_endpoint_auth_signing_alg: only RS256 and ES256 are supported",
		)
	}
}
