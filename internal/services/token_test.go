package services

import (
	"context"
	"testing"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/metrics"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/token"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestTokenService(s *store.Store, cfg *config.Config) *TokenService {
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())
	localProvider := token.NewLocalTokenProvider(cfg)
	return NewTokenService(
		s,
		cfg,
		deviceService,
		localProvider,
		nil,
		"local",
		nil,
		metrics.NewNoopMetrics(),
	)
}

func createAuthorizedDeviceCode(t *testing.T, s *store.Store, clientID string) *models.DeviceCode {
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Generate device code
	dc, err := deviceService.GenerateDeviceCode(context.Background(), clientID, "read write")
	require.NoError(t, err)

	// Authorize it
	userID := uuid.New().String()
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc.UserCode, userID, "testuser")
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
	tokenService := createTestTokenService(s, cfg)

	// Create an active client and authorized device code
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)

	// Exchange device code for token
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)

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
	tokenService := createTestTokenService(s, cfg)
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)

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
	tokenService := createTestTokenService(s, cfg)

	// Create an active client and authorized device code
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)

	// Try to exchange with a different client ID
	differentClientID := uuid.New().String()
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		differentClientID,
	)

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
	tokenService := createTestTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client and device code but don't authorize it
	client := createTestClient(t, s, true)
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")
	require.NoError(t, err)

	// Try to exchange without authorization
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)

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
	tokenService := createTestTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client and device code (it will be expired)
	client := createTestClient(t, s, true)
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")
	require.NoError(t, err)

	// Try to exchange expired device code
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)

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
	tokenService := createTestTokenService(s, cfg)

	// Create an active client
	client := createTestClient(t, s, true)

	// Try to exchange with non-existent device code
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		"non-existent-code",
		client.ClientID,
	)

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
	tokenService := createTestTokenService(s, cfg)

	// Create an active client and get a token
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// Validate the token
	claims, err := tokenService.ValidateToken(context.Background(), token.Token)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, client.ClientID, claims.ClientID)
	assert.Equal(t, "read write", claims.Scopes)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}
	tokenService := createTestTokenService(s, cfg)

	// Try to validate an invalid token
	claims, err := tokenService.ValidateToken(context.Background(), "invalid-token")

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
	tokenService := createTestTokenService(s, cfg)

	// Create an active client and get a token
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// Try to validate with different secret
	differentCfg := &config.Config{
		JWTSecret: "different-secret",
	}
	differentTokenService := createTestTokenService(s, differentCfg)
	claims, err := differentTokenService.ValidateToken(context.Background(), token.Token)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestRevokeToken_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(s, cfg)

	// Create an active client and get a token
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// Revoke the token
	err = tokenService.RevokeToken(token.Token)

	// Assert
	assert.NoError(t, err)

	// Verify token is removed from database
	_, err = s.GetAccessToken(token.Token)
	assert.Error(t, err) // Should not be found
}

func TestRevokeToken_InvalidToken(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}
	tokenService := createTestTokenService(s, cfg)

	// Try to revoke a non-existent token
	err := tokenService.RevokeToken("non-existent-token")

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token not found")
}

func TestRevokeTokenByID_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(s, cfg)

	// Create an active client and get a token
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	token, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// Revoke the token by ID
	err = tokenService.RevokeTokenByID(context.Background(), token.ID, dc.UserID)

	// Assert
	assert.NoError(t, err)

	// Verify token is removed from database
	_, err = s.GetAccessTokenByID(token.ID)
	assert.Error(t, err) // Should not be found
}

func TestGetUserTokens_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client
	client := createTestClient(t, s, true)
	userID := uuid.New().String()

	// Generate and authorize multiple device codes
	dc1, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read")
	require.NoError(t, err)
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc1.UserCode, userID, "testuser")
	require.NoError(t, err)

	dc2, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "write")
	require.NoError(t, err)
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc2.UserCode, userID, "testuser")
	require.NoError(t, err)

	// Exchange for tokens
	token1, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc1.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)
	token2, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc2.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// Get user tokens
	tokens, err := tokenService.GetUserTokens(userID)

	// Assert - should have 4 tokens (2 access + 2 refresh)
	assert.NoError(t, err)
	assert.Len(t, tokens, 4)
	// Verify we have tokens from both device code exchanges
	tokenIDs := make([]string, len(tokens))
	for i, tok := range tokens {
		tokenIDs[i] = tok.ID
	}
	assert.Contains(t, tokenIDs, token1.ID)
	assert.Contains(t, tokenIDs, token2.ID)
}

func TestRevokeAllUserTokens_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client
	client := createTestClient(t, s, true)
	userID := uuid.New().String()

	// Generate and authorize multiple device codes
	dc1, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read")
	require.NoError(t, err)
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc1.UserCode, userID, "testuser")
	require.NoError(t, err)

	dc2, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "write")
	require.NoError(t, err)
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc2.UserCode, userID, "testuser")
	require.NoError(t, err)

	// Exchange for tokens
	_, _, err = tokenService.ExchangeDeviceCode(
		context.Background(),
		dc1.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)
	_, _, err = tokenService.ExchangeDeviceCode(
		context.Background(),
		dc2.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// Revoke all user tokens
	err = tokenService.RevokeAllUserTokens(userID)
	assert.NoError(t, err)

	// Verify all tokens are removed
	tokens, err := tokenService.GetUserTokens(userID)
	assert.NoError(t, err)
	assert.Len(t, tokens, 0)
}

func TestGetUserTokensWithClient_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client
	client := createTestClient(t, s, true)
	userID := uuid.New().String()

	// Generate and authorize device code
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")
	require.NoError(t, err)
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc.UserCode, userID, "testuser")
	require.NoError(t, err)

	// Exchange for token (returns both access and refresh tokens)
	accessToken, refreshToken, err := tokenService.ExchangeDeviceCode(context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// Get user tokens with client info
	tokensWithClient, err := tokenService.GetUserTokensWithClient(userID)

	// Assert - should have 2 tokens (access + refresh)
	assert.NoError(t, err)
	assert.Len(t, tokensWithClient, 2)

	// Verify both tokens are present
	tokenIDs := []string{accessToken.ID, refreshToken.ID}
	for _, twc := range tokensWithClient {
		assert.Contains(t, tokenIDs, twc.ID)
		assert.Equal(t, client.ClientName, twc.ClientName)
		assert.Equal(t, "read write", twc.Scopes)
	}
}

func TestGetUserTokensWithClient_MultipleClients(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(s, cfg)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create two different clients
	client1 := createTestClient(t, s, true)
	client2 := createTestClient(t, s, true)
	userID := uuid.New().String()

	// Generate and authorize tokens for both clients
	dc1, err := deviceService.GenerateDeviceCode(context.Background(), client1.ClientID, "read")
	require.NoError(t, err)
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc1.UserCode, userID, "testuser")
	require.NoError(t, err)

	dc2, err := deviceService.GenerateDeviceCode(context.Background(), client2.ClientID, "write")
	require.NoError(t, err)
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc2.UserCode, userID, "testuser")
	require.NoError(t, err)

	// Exchange for tokens
	token1, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc1.DeviceCode,
		client1.ClientID,
	)
	require.NoError(t, err)
	token2, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc2.DeviceCode,
		client2.ClientID,
	)
	require.NoError(t, err)

	// Get user tokens with client info (should use WHERE IN for batch query)
	tokensWithClient, err := tokenService.GetUserTokensWithClient(userID)

	// Assert - should have 4 tokens (2 access + 2 refresh)
	assert.NoError(t, err)
	assert.Len(t, tokensWithClient, 4)

	// Create maps for easier verification
	tokenMap := make(map[string]TokenWithClient)
	for _, twc := range tokensWithClient {
		tokenMap[twc.ID] = twc
	}

	// Verify token 1
	assert.Contains(t, tokenMap, token1.ID)
	assert.Equal(t, client1.ClientName, tokenMap[token1.ID].ClientName)
	assert.Equal(t, "read", tokenMap[token1.ID].Scopes)

	// Verify token 2
	assert.Contains(t, tokenMap, token2.ID)
	assert.Equal(t, client2.ClientName, tokenMap[token2.ID].ClientName)
	assert.Equal(t, "write", tokenMap[token2.ID].Scopes)
}

func TestGetUserTokensWithClient_EmptyResult(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}
	tokenService := createTestTokenService(s, cfg)

	// Get tokens for non-existent user
	tokensWithClient, err := tokenService.GetUserTokensWithClient("non-existent-user")

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, tokensWithClient)
	assert.Len(t, tokensWithClient, 0)
}

// ============================================================
// ExchangeAuthorizationCode
// ============================================================

func createTestAuthCodeRecord(
	t *testing.T,
	s *store.Store,
	client *models.OAuthApplication,
	userID string,
) *models.AuthorizationCode {
	t.Helper()
	now := time.Now()
	code := &models.AuthorizationCode{
		UUID:          "test-uuid-" + uuid.New().String(),
		CodeHash:      "hash-" + uuid.New().String(),
		CodePrefix:    "testpfx1",
		ApplicationID: client.ID,
		ClientID:      client.ClientID,
		UserID:        userID,
		RedirectURI:   "https://app.example.com/callback",
		Scopes:        "read write",
		ExpiresAt:     now.Add(10 * time.Minute),
	}
	require.NoError(t, s.CreateAuthorizationCode(code))
	return code
}

func TestExchangeAuthorizationCode_IssuesTokens(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret",
		BaseURL:                "http://localhost:8080",
		EnableRefreshTokens:    true,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
	}
	tokenService := createTestTokenService(s, cfg)

	client := createTestClient(t, s, true)
	userID := uuid.New().String()
	authCode := createTestAuthCodeRecord(t, s, client, userID)

	accessToken, refreshToken, err := tokenService.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		nil, // no authorization ID
	)

	require.NoError(t, err)
	require.NotNil(t, accessToken)
	assert.NotEmpty(t, accessToken.Token)
	assert.Equal(t, "Bearer", accessToken.TokenType)
	assert.Equal(t, userID, accessToken.UserID)
	assert.Equal(t, client.ClientID, accessToken.ClientID)
	assert.Equal(t, "read write", accessToken.Scopes)
	assert.NotNil(t, refreshToken)
}

func TestExchangeAuthorizationCode_WithAuthorizationID(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret",
		BaseURL:                "http://localhost:8080",
		EnableRefreshTokens:    true,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
	}
	tokenService := createTestTokenService(s, cfg)

	client := createTestClient(t, s, true)
	userID := uuid.New().String()
	authCode := createTestAuthCodeRecord(t, s, client, userID)

	// Simulate a UserAuthorization ID being set
	authID := uint(42)
	accessToken, _, err := tokenService.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		&authID,
	)

	require.NoError(t, err)
	require.NotNil(t, accessToken)
	assert.Equal(t, &authID, accessToken.AuthorizationID)
}
