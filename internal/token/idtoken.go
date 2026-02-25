package token

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// IDTokenParams holds all data needed to generate an OIDC ID Token (OIDC Core 1.0 §2).
type IDTokenParams struct {
	Issuer   string
	Subject  string // UserID
	Audience string // ClientID
	AuthTime time.Time
	Nonce    string
	Expiry   time.Duration
	AtHash   string // base64url(SHA-256(access_token)[:16]) – optional

	// Scope-gated profile claims (include when "profile" scope was granted)
	Name              string
	PreferredUsername string
	Picture           string
	UpdatedAt         *time.Time

	// Scope-gated email claims (include when "email" scope was granted)
	Email         string
	EmailVerified bool
}

// GenerateIDToken creates a signed HS256 JWT ID Token for the given params.
// ID tokens are not stored in the database; they are short-lived and non-revocable by design.
func (p *LocalTokenProvider) GenerateIDToken(params IDTokenParams) (string, error) {
	now := time.Now()
	expiry := params.Expiry
	if expiry <= 0 {
		expiry = p.config.JWTExpiration
	}

	claims := jwt.MapClaims{
		"iss":       params.Issuer,
		"sub":       params.Subject,
		"aud":       params.Audience,
		"exp":       now.Add(expiry).Unix(),
		"iat":       now.Unix(),
		"auth_time": params.AuthTime.Unix(),
		"jti":       uuid.New().String(),
	}

	if params.Nonce != "" {
		claims["nonce"] = params.Nonce
	}
	if params.AtHash != "" {
		claims["at_hash"] = params.AtHash
	}

	// Profile claims
	if params.Name != "" {
		claims["name"] = params.Name
	}
	if params.PreferredUsername != "" {
		claims["preferred_username"] = params.PreferredUsername
	}
	if params.Picture != "" {
		claims["picture"] = params.Picture
	}
	if params.UpdatedAt != nil {
		claims["updated_at"] = params.UpdatedAt.Unix()
	}

	// Email claims
	if params.Email != "" {
		claims["email"] = params.Email
		claims["email_verified"] = params.EmailVerified
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(p.config.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}
	return tokenString, nil
}

// ComputeAtHash computes the at_hash claim value per OIDC Core 1.0 §3.3.2.11.
// at_hash = base64url( left-most 128 bits of SHA-256( ASCII(access_token) ) )
func ComputeAtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// ScopeSet parses a space-separated scope string into a boolean lookup map.
func ScopeSet(scopes string) map[string]bool {
	set := make(map[string]bool)
	for s := range strings.FieldsSeq(scopes) {
		set[s] = true
	}
	return set
}
