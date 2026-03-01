package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/token"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createConfidentialClientWithCCFlow creates a confidential client with CC flow enabled and returns
// both the model and the plaintext secret for use in tests.
func createConfidentialClientWithCCFlow(
	t *testing.T,
	s *store.Store,
	enableCCFlow bool,
) (*models.OAuthApplication, string) {
	t.Helper()
	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "M2M Service",
		UserID:                      uuid.New().String(),
		Scopes:                      "read write",
		GrantTypes:                  "client_credentials",
		ClientType:                  ClientTypeConfidential,
		EnableClientCredentialsFlow: enableCCFlow,
		IsActive:                    true,
	}
	plainSecret, err := client.GenerateClientSecret(context.Background())
	require.NoError(t, err)
	err = s.CreateClient(client)
	require.NoError(t, err)
	return client, plainSecret
}

func newCCTokenService(t *testing.T) (*TokenService, *store.Store) {
	t.Helper()
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:                    1 * time.Hour,
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		JWTSecret:                        "test-secret",
		BaseURL:                          "http://localhost:8080",
	}
	localProvider := token.NewLocalTokenProvider(cfg)
	svc := NewTokenService(
		s,
		cfg,
		nil,
		localProvider,
		nil,
		metrics.NewNoopMetrics(),
	)
	return svc, s
}

// --- Success cases ---

func TestIssueClientCredentialsToken_Success_DefaultScopes(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	tok, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"",
	)

	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.NotEmpty(t, tok.RawToken)
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.Equal(t, "access", tok.TokenCategory)
	assert.Equal(t, "active", tok.Status)
	assert.Equal(t, client.ClientID, tok.ClientID)
	// When no scope is requested, all client scopes are granted
	assert.Equal(t, "read write", tok.Scopes)
	// UserID must use the machine identity prefix
	assert.Equal(t, "client:"+client.ClientID, tok.UserID)
	// Token must not have expired yet
	assert.True(t, tok.ExpiresAt.After(time.Now()))
}

func TestIssueClientCredentialsToken_Success_SubsetScopes(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	tok, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"read",
	)

	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.Equal(t, "read", tok.Scopes)
}

// --- Failure: client type ---

func TestIssueClientCredentialsToken_Error_PublicClient(t *testing.T) {
	svc, s := newCCTokenService(t)
	// Create a public client
	publicClient := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "SPA",
		UserID:                      uuid.New().String(),
		Scopes:                      "read",
		GrantTypes:                  "authorization_code",
		ClientType:                  ClientTypePublic,
		EnableClientCredentialsFlow: false,
		IsActive:                    true,
	}
	_, err := publicClient.GenerateClientSecret(context.Background())
	require.NoError(t, err)
	require.NoError(t, s.CreateClient(publicClient))
	plainSecret, err := publicClient.GenerateClientSecret(context.Background())
	require.NoError(t, err)
	require.NoError(t, s.UpdateClient(publicClient))

	_, err = svc.IssueClientCredentialsToken(
		context.Background(),
		publicClient.ClientID,
		plainSecret,
		"",
	)
	assert.ErrorIs(t, err, ErrClientNotConfidential)
}

// --- Failure: flow disabled ---

func TestIssueClientCredentialsToken_Error_FlowDisabled(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, false) // flow disabled

	_, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"",
	)
	assert.ErrorIs(t, err, ErrClientCredentialsFlowDisabled)
}

// --- Failure: wrong secret ---

func TestIssueClientCredentialsToken_Error_WrongSecret(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, _ := createConfidentialClientWithCCFlow(t, s, true)

	_, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		"wrong-secret",
		"",
	)
	assert.ErrorIs(t, err, ErrInvalidClientCredentials)
}

// --- Failure: inactive client ---

func TestIssueClientCredentialsToken_Error_InactiveClient(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	// Deactivate
	client.IsActive = false
	require.NoError(t, s.UpdateClient(client))

	_, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"",
	)
	assert.ErrorIs(t, err, ErrInvalidClientCredentials)
}

// --- Failure: scope exceeds client scopes ---

func TestIssueClientCredentialsToken_Error_ScopeExceedsClient(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true) // scopes: "read write"

	_, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"read write admin",
	)
	assert.ErrorIs(t, err, token.ErrInvalidScope)
}

// --- Failure: restricted OIDC scopes ---

func TestIssueClientCredentialsToken_Error_OpenIDScope(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	_, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"openid read",
	)
	assert.ErrorIs(t, err, token.ErrInvalidScope)
}

func TestIssueClientCredentialsToken_Error_OfflineAccessScope(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	_, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"offline_access read",
	)
	assert.ErrorIs(t, err, token.ErrInvalidScope)
}

// --- Verify token is persisted and queryable ---

func TestIssueClientCredentialsToken_TokenPersisted(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	tok, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"",
	)
	require.NoError(t, err)

	// Validate through the service — token must be in the database
	result, err := svc.ValidateToken(context.Background(), tok.RawToken)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "client:"+client.ClientID, result.UserID)
	assert.Equal(t, client.ClientID, result.ClientID)
}

// --- Verify machine UserID prefix ---

func TestIssueClientCredentialsToken_MachineUserIDPrefix(t *testing.T) {
	svc, s := newCCTokenService(t)
	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	tok, err := svc.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"",
	)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(tok.UserID, "client:"),
		"client credentials token UserID must start with 'client:' prefix, got: %s", tok.UserID)
	assert.False(t, strings.HasPrefix(tok.UserID, "client:client:"),
		"prefix must not be doubled")
}
