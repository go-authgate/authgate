package services

import (
	"testing"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createAuthorizedDeviceCode(t *testing.T, s *store.Store, clientID string) *models.DeviceCode {
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg)

	// Generate device code
	dc, err := deviceService.GenerateDeviceCode(clientID, "read write")
	require.NoError(t, err)

	// Authorize it
	userID := uuid.New().String()
	err = deviceService.AuthorizeDeviceCode(dc.UserCode, userID)
	require.NoError(t, err)

	// Return the authorized device code
	return dc
}

func TestExchangeDeviceCode_ActiveClient(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := NewTokenService(s, cfg)

	// Create an active client and authorized device code
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)

	// Exchange device code for token
	token, err := tokenService.ExchangeDeviceCode(dc.DeviceCode, client.ClientID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.NotEmpty(t, token.Token)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, client.ClientID, token.ClientID)
	assert.Equal(t, "read write", token.Scopes)
}

func TestExchangeDeviceCode_InactiveClient(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}

	// Create an active client and generate device code
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)

	// Now deactivate the client
	client.IsActive = false
	err := s.UpdateClient(client)
	require.NoError(t, err)

	// Try to exchange device code with inactive client
	tokenService := NewTokenService(s, cfg)
	token, err := tokenService.ExchangeDeviceCode(dc.DeviceCode, client.ClientID)

	// Assert - should fail with access denied
	assert.Error(t, err)
	assert.Equal(t, ErrAccessDenied, err)
	assert.Nil(t, token)
}

func TestExchangeDeviceCode_ClientMismatch(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := NewTokenService(s, cfg)

	// Create an active client and authorized device code
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)

	// Try to exchange with a different client ID
	differentClientID := uuid.New().String()
	token, err := tokenService.ExchangeDeviceCode(dc.DeviceCode, differentClientID)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrAccessDenied, err)
	assert.Nil(t, token)
}

func TestExchangeDeviceCode_NotAuthorized(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := NewTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg)

	// Create an active client and device code but don't authorize it
	client := createTestClient(t, s, true)
	dc, err := deviceService.GenerateDeviceCode(client.ClientID, "read write")
	require.NoError(t, err)

	// Try to exchange without authorization
	token, err := tokenService.ExchangeDeviceCode(dc.DeviceCode, client.ClientID)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrAuthorizationPending, err)
	assert.Nil(t, token)
}

func TestExchangeDeviceCode_ExpiredCode(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: -1 * time.Minute, // Negative expiration for expired code
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := NewTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg)

	// Create an active client and device code (it will be expired)
	client := createTestClient(t, s, true)
	dc, err := deviceService.GenerateDeviceCode(client.ClientID, "read write")
	require.NoError(t, err)

	// Try to exchange expired device code
	token, err := tokenService.ExchangeDeviceCode(dc.DeviceCode, client.ClientID)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
	assert.Nil(t, token)
}

func TestExchangeDeviceCode_InvalidDeviceCode(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := NewTokenService(s, cfg)

	// Create an active client
	client := createTestClient(t, s, true)

	// Try to exchange with non-existent device code
	token, err := tokenService.ExchangeDeviceCode("non-existent-code", client.ClientID)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
	assert.Nil(t, token)
}

func TestValidateToken_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := NewTokenService(s, cfg)

	// Create an active client and get a token
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	token, err := tokenService.ExchangeDeviceCode(dc.DeviceCode, client.ClientID)
	require.NoError(t, err)

	// Validate the token
	claims, err := tokenService.ValidateToken(token.Token)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, client.ClientID, claims.ClientID)
	assert.Equal(t, "read write", claims.Scopes)
	assert.Equal(t, cfg.BaseURL, claims.Issuer)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}
	tokenService := NewTokenService(s, cfg)

	// Try to validate an invalid token
	claims, err := tokenService.ValidateToken("invalid-token")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_WrongSecret(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := NewTokenService(s, cfg)

	// Create an active client and get a token
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	token, err := tokenService.ExchangeDeviceCode(dc.DeviceCode, client.ClientID)
	require.NoError(t, err)

	// Try to validate with different secret
	differentCfg := &config.Config{
		JWTSecret: "different-secret",
	}
	differentTokenService := NewTokenService(s, differentCfg)
	claims, err := differentTokenService.ValidateToken(token.Token)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
}
