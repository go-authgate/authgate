package services

import (
	"errors"
	"time"

	"github.com/appleboy/authgate/config"
	"github.com/appleboy/authgate/models"
	"github.com/appleboy/authgate/store"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
)

type TokenService struct {
	store  *store.Store
	config *config.Config
}

type JWTClaims struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	Scopes   string `json:"scope"`
	jwt.RegisteredClaims
}

func NewTokenService(s *store.Store, cfg *config.Config) *TokenService {
	return &TokenService{store: s, config: cfg}
}

// ExchangeDeviceCode exchanges an authorized device code for an access token
func (s *TokenService) ExchangeDeviceCode(deviceCode, clientID string) (*models.AccessToken, error) {
	dc, err := s.store.GetDeviceCode(deviceCode)
	if err != nil {
		return nil, ErrExpiredToken
	}

	// Check if expired
	if dc.IsExpired() {
		s.store.DeleteDeviceCode(deviceCode)
		return nil, ErrExpiredToken
	}

	// Check if client matches
	if dc.ClientID != clientID {
		return nil, ErrAccessDenied
	}

	// Check if authorized
	if !dc.Authorized {
		return nil, ErrAuthorizationPending
	}

	// Generate JWT token
	expiresAt := time.Now().Add(s.config.JWTExpiration)
	claims := &JWTClaims{
		UserID:   dc.UserID,
		ClientID: dc.ClientID,
		Scopes:   dc.Scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.BaseURL,
			Subject:   dc.UserID,
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		return nil, err
	}

	// Create access token record
	accessToken := &models.AccessToken{
		ID:        uuid.New().String(),
		Token:     tokenString,
		TokenType: "Bearer",
		UserID:    dc.UserID,
		ClientID:  dc.ClientID,
		Scopes:    dc.Scopes,
		ExpiresAt: expiresAt,
	}

	if err := s.store.CreateAccessToken(accessToken); err != nil {
		return nil, err
	}

	// Delete the used device code
	s.store.DeleteDeviceCode(deviceCode)

	return accessToken, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *TokenService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
