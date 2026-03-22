package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIntrospectTokenService(t *testing.T) (*TokenService, *store.Store) {
	t.Helper()
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:                    1 * time.Hour,
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		JWTSecret:                        "test-secret",
		BaseURL:                          "http://localhost:8080",
	}
	localProvider, err := token.NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	svc := NewTokenService(s, cfg, nil, localProvider, nil, metrics.NewNoopMetrics())
	return svc, s
}

func createTestAccessToken(
	t *testing.T,
	s *store.Store,
	rawToken, userID, clientID, status string,
	expiresAt time.Time,
) *models.AccessToken {
	t.Helper()
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(rawToken),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        status,
		UserID:        userID,
		ClientID:      clientID,
		Scopes:        "read write",
		ExpiresAt:     expiresAt,
	}
	require.NoError(t, s.DB().Create(tok).Error)
	return tok
}

func TestIntrospectToken_ActiveToken(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	rawToken := "active-test-token-" + uuid.New().String()
	createTestAccessToken(t, s, rawToken, "user-1", "client-1",
		models.TokenStatusActive, time.Now().Add(1*time.Hour))

	tok, active := svc.IntrospectToken(context.Background(), rawToken, "test-client")
	assert.True(t, active)
	require.NotNil(t, tok)
	assert.Equal(t, "user-1", tok.UserID)
	assert.Equal(t, "client-1", tok.ClientID)
	assert.Equal(t, "read write", tok.Scopes)
}

func TestIntrospectToken_ExpiredToken(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	rawToken := "expired-test-token-" + uuid.New().String()
	createTestAccessToken(t, s, rawToken, "user-1", "client-1",
		models.TokenStatusActive, time.Now().Add(-1*time.Hour))

	tok, active := svc.IntrospectToken(context.Background(), rawToken, "test-client")
	assert.False(t, active)
	require.NotNil(t, tok, "expired token should still be returned for metadata")
}

func TestIntrospectToken_RevokedToken(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	rawToken := "revoked-test-token-" + uuid.New().String()
	createTestAccessToken(t, s, rawToken, "user-1", "client-1",
		models.TokenStatusRevoked, time.Now().Add(1*time.Hour))

	tok, active := svc.IntrospectToken(context.Background(), rawToken, "test-client")
	assert.False(t, active)
	require.NotNil(t, tok)
}

func TestIntrospectToken_DisabledToken(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	rawToken := "disabled-test-token-" + uuid.New().String()
	createTestAccessToken(t, s, rawToken, "user-1", "client-1",
		models.TokenStatusDisabled, time.Now().Add(1*time.Hour))

	tok, active := svc.IntrospectToken(context.Background(), rawToken, "test-client")
	assert.False(t, active)
	require.NotNil(t, tok)
}

func TestIntrospectToken_NonexistentToken(t *testing.T) {
	svc, _ := newIntrospectTokenService(t)

	tok, active := svc.IntrospectToken(context.Background(), "does-not-exist", "test-client")
	assert.False(t, active)
	assert.Nil(t, tok)
}

func TestAuthenticateClient_Success(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)
	err := svc.AuthenticateClient(client.ClientID, plainSecret)
	assert.NoError(t, err)
}

func TestAuthenticateClient_WrongSecret(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	client, _ := createConfidentialClientWithCCFlow(t, s, true)
	err := svc.AuthenticateClient(client.ClientID, "wrong-secret")
	assert.ErrorIs(t, err, ErrInvalidClientCredentials)
}

func TestAuthenticateClient_NonexistentClient(t *testing.T) {
	svc, _ := newIntrospectTokenService(t)

	err := svc.AuthenticateClient("nonexistent-client-id", "any-secret")
	assert.ErrorIs(t, err, ErrInvalidClientCredentials)
}

func TestAuthenticateClient_InactiveClient(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	// Create a confidential client with CC flow, then deactivate it
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)
	client.Status = models.ClientStatusInactive
	require.NoError(t, s.UpdateClient(client))

	err := svc.AuthenticateClient(client.ClientID, plainSecret)
	assert.ErrorIs(t, err, ErrInvalidClientCredentials)
}

func TestGetUserByID_Success(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	user := &models.User{
		ID:       uuid.New().String(),
		Username: "introspect-user",
		Email:    "introspect@example.com",
		Role:     models.UserRoleUser,
	}
	require.NoError(t, s.DB().Create(user).Error)

	result, err := svc.GetUserByID(user.ID)
	require.NoError(t, err)
	assert.Equal(t, "introspect-user", result.Username)
}

func TestGetUserByID_NotFound(t *testing.T) {
	svc, _ := newIntrospectTokenService(t)

	_, err := svc.GetUserByID("nonexistent-user-id")
	assert.Error(t, err)
}

func TestIntrospectToken_WithClientCredentialsFlow(t *testing.T) {
	svc, s := newIntrospectTokenService(t)

	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	// Issue a real token via the service
	tok, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"",
	)
	require.NoError(t, err)

	// Introspect it
	introspected, active := svc.IntrospectToken(context.Background(), tok.RawToken, client.ClientID)
	assert.True(t, active)
	require.NotNil(t, introspected)
	assert.Equal(t, "client:"+client.ClientID, introspected.UserID)
	assert.Equal(t, client.ClientID, introspected.ClientID)
}
