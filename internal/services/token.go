package services

import (
	"errors"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenWithClient combines token and client information for display
type TokenWithClient struct {
	models.AccessToken
	ClientName string
}

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
func (s *TokenService) ExchangeDeviceCode(
	deviceCode, clientID string,
) (*models.AccessToken, error) {
	dc, err := s.store.GetDeviceCode(deviceCode)
	if err != nil {
		return nil, ErrExpiredToken
	}

	// Check if expired
	if dc.IsExpired() {
		_ = s.store.DeleteDeviceCode(deviceCode)
		return nil, ErrExpiredToken
	}

	// Check if client matches
	if dc.ClientID != clientID {
		return nil, ErrAccessDenied
	}

	// Check if client is active
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return nil, ErrAccessDenied
	}
	if !client.IsActive {
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
	_ = s.store.DeleteDeviceCode(deviceCode)

	return accessToken, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *TokenService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&JWTClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(s.config.JWTSecret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RevokeToken revokes a token by its JWT string
func (s *TokenService) RevokeToken(tokenString string) error {
	// Get the token from database
	token, err := s.store.GetAccessToken(tokenString)
	if err != nil {
		return errors.New("token not found")
	}

	// Delete the token
	return s.store.RevokeToken(token.ID)
}

// RevokeTokenByID revokes a token by its ID
func (s *TokenService) RevokeTokenByID(tokenID string) error {
	return s.store.RevokeToken(tokenID)
}

// GetUserTokens returns all active tokens for a user
func (s *TokenService) GetUserTokens(userID string) ([]models.AccessToken, error) {
	return s.store.GetTokensByUserID(userID)
}

// GetUserTokensWithClient returns all active tokens for a user with client information
func (s *TokenService) GetUserTokensWithClient(userID string) ([]TokenWithClient, error) {
	tokens, err := s.store.GetTokensByUserID(userID)
	if err != nil {
		return nil, err
	}

	if len(tokens) == 0 {
		return []TokenWithClient{}, nil
	}

	// Collect unique client IDs
	clientIDSet := make(map[string]bool)
	for _, token := range tokens {
		clientIDSet[token.ClientID] = true
	}

	clientIDs := make([]string, 0, len(clientIDSet))
	for clientID := range clientIDSet {
		clientIDs = append(clientIDs, clientID)
	}

	// Batch query all clients using WHERE IN
	clientMap, err := s.store.GetClientsByIDs(clientIDs)
	if err != nil {
		return nil, err
	}

	// Combine tokens with client information
	result := make([]TokenWithClient, 0, len(tokens))
	for _, token := range tokens {
		clientName := token.ClientID // Default to ClientID if not found
		if client, ok := clientMap[token.ClientID]; ok && client != nil {
			clientName = client.ClientName
		}

		result = append(result, TokenWithClient{
			AccessToken: token,
			ClientName:  clientName,
		})
	}

	return result, nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (s *TokenService) RevokeAllUserTokens(userID string) error {
	return s.store.RevokeTokensByUserID(userID)
}
