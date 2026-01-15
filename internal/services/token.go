package services

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/token"

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
	store              *store.Store
	config             *config.Config
	localTokenProvider *token.LocalTokenProvider
	httpTokenProvider  *token.HTTPTokenProvider
	tokenProviderMode  string
}

type JWTClaims struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	Scopes   string `json:"scope"`
	jwt.RegisteredClaims
}

func NewTokenService(
	s *store.Store,
	cfg *config.Config,
	localProvider *token.LocalTokenProvider,
	httpProvider *token.HTTPTokenProvider,
	providerMode string,
) *TokenService {
	return &TokenService{
		store:              s,
		config:             cfg,
		localTokenProvider: localProvider,
		httpTokenProvider:  httpProvider,
		tokenProviderMode:  providerMode,
	}
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

	// Generate JWT token using provider
	var tokenResult *token.TokenResult
	var providerErr error

	switch s.tokenProviderMode {
	case "http_api":
		if s.httpTokenProvider == nil {
			return nil, fmt.Errorf(
				"HTTP token provider not configured (TOKEN_PROVIDER_MODE=http_api requires TOKEN_API_URL)",
			)
		}
		tokenResult, providerErr = s.httpTokenProvider.GenerateToken(
			context.Background(),
			dc.UserID,
			dc.ClientID,
			dc.Scopes,
		)
	case "local":
		fallthrough
	default:
		if s.localTokenProvider == nil {
			return nil, fmt.Errorf("local token provider not configured")
		}
		tokenResult, providerErr = s.localTokenProvider.GenerateToken(
			context.Background(),
			dc.UserID,
			dc.ClientID,
			dc.Scopes,
		)
	}

	if providerErr != nil {
		log.Printf("[Token] Generation failed provider=%s: %v", s.tokenProviderMode, providerErr)
		return nil, fmt.Errorf("token generation failed: %w", providerErr)
	}

	if !tokenResult.Success {
		return nil, fmt.Errorf("token generation unsuccessful")
	}

	// Create access token record
	accessToken := &models.AccessToken{
		ID:        uuid.New().String(),
		Token:     tokenResult.TokenString,
		TokenType: tokenResult.TokenType,
		UserID:    dc.UserID,
		ClientID:  dc.ClientID,
		Scopes:    dc.Scopes,
		ExpiresAt: tokenResult.ExpiresAt,
	}

	if err := s.store.CreateAccessToken(accessToken); err != nil {
		return nil, err
	}

	// Delete the used device code
	_ = s.store.DeleteDeviceCode(deviceCode)

	return accessToken, nil
}

// ValidateToken validates a JWT token using the configured provider
func (s *TokenService) ValidateToken(tokenString string) (*token.TokenValidationResult, error) {
	var result *token.TokenValidationResult
	var err error

	switch s.tokenProviderMode {
	case "http_api":
		if s.httpTokenProvider == nil {
			return nil, fmt.Errorf("HTTP token provider not configured")
		}
		result, err = s.httpTokenProvider.ValidateToken(context.Background(), tokenString)
	case "local":
		fallthrough
	default:
		if s.localTokenProvider == nil {
			return nil, fmt.Errorf("local token provider not configured")
		}
		result, err = s.localTokenProvider.ValidateToken(context.Background(), tokenString)
	}

	if err != nil {
		return nil, err
	}

	// Optional: Check if token exists in database (for revocation check)
	// This adds an extra layer of security
	_, dbErr := s.store.GetAccessToken(tokenString)
	if dbErr != nil {
		// Token was revoked or doesn't exist in our records
		return nil, errors.New("token not found or revoked")
	}

	return result, nil
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
