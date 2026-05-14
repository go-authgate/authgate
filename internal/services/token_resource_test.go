package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestAuthCodeFlow_WithResource_PropagatesToAud is the RFC 8707 happy path:
// the authorize-time resource indicator must be bound to the access token's
// "aud" claim at token-exchange time. JWTAudience config is intentionally
// non-empty to prove the resource indicator wins.
func TestAuthCodeFlow_WithResource_PropagatesToAud(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret-aud",
		BaseURL:                "http://localhost:8080",
		JWTAudience:            []string{"static.example.com"},
		EnableRefreshTokens:    true,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
	}
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	userID := uuid.New().String()
	now := time.Now()
	authCode := &models.AuthorizationCode{
		UUID:          "test-uuid-" + uuid.New().String(),
		CodeHash:      "hash-" + uuid.New().String(),
		CodePrefix:    "rsrcpfx1",
		ApplicationID: client.ID,
		ClientID:      client.ClientID,
		UserID:        userID,
		RedirectURI:   "https://app.example.com/callback",
		Scopes:        "read write",
		Resource:      models.StringArray{"https://mcp.example.com"},
		ExpiresAt:     now.Add(10 * time.Minute),
	}
	require.NoError(t, s.CreateAuthorizationCode(authCode))

	accessToken, _, _, err := tokenService.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		nil, nil,
		// Token-time resource matches the authorize-time grant.
		[]string{"https://mcp.example.com"},
	)
	require.NoError(t, err)

	// Decode the access token and assert the audience binding.
	claims := decodeJWTClaims(t, accessToken.RawToken)
	// Single value collapses to a plain string per audienceClaim().
	aud, ok := claims["aud"].(string)
	require.True(t, ok, "aud must be a string for a single-value resource")
	assert.Equal(t, "https://mcp.example.com", aud)

	// The persisted token row must carry the resource so refresh can enforce
	// RFC 8707 §2.2 subset rules later.
	assert.Equal(
		t,
		models.StringArray{"https://mcp.example.com"},
		accessToken.Resource,
	)
}

// TestRefresh_RejectsResourceSupersetOfOriginal exercises RFC 8707 §2.2:
// the refresh request may narrow the audience but never widen it. Passing
// a resource not in the original grant must return ErrInvalidTarget.
func TestRefresh_RejectsResourceSupersetOfOriginal(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret-refresh-resource",
		BaseURL:                "http://localhost:8080",
		EnableRefreshTokens:    true,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
	}
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	userID := uuid.New().String()
	now := time.Now()
	authCode := &models.AuthorizationCode{
		UUID:          "test-uuid-" + uuid.New().String(),
		CodeHash:      "hash-" + uuid.New().String(),
		CodePrefix:    "rsrcpfx2",
		ApplicationID: client.ID,
		ClientID:      client.ClientID,
		UserID:        userID,
		RedirectURI:   "https://app.example.com/callback",
		Scopes:        "read write",
		Resource:      models.StringArray{"https://mcp.example.com"},
		ExpiresAt:     now.Add(10 * time.Minute),
	}
	require.NoError(t, s.CreateAuthorizationCode(authCode))

	_, refreshToken, _, err := tokenService.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		nil, nil,
		[]string{"https://mcp.example.com"},
	)
	require.NoError(t, err)
	require.NotNil(t, refreshToken)

	// Attempt to widen audience to a resource that was never granted.
	_, _, err = tokenService.RefreshAccessToken(
		context.Background(),
		refreshToken.RawToken,
		client.ClientID,
		"", // requestedScopes
		nil,
		[]string{"https://forbidden.example.com"},
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTarget)
}

// TestClientCredentials_WithResource_PropagatesToAud confirms the
// client_credentials grant honors RFC 8707 resource: the requested resource
// becomes the issued JWT's `aud` and is persisted on the token row.
func TestClientCredentials_WithResource_PropagatesToAud(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		BaseURL:                          "http://localhost:8080",
		JWTSecret:                        "test-secret-cc-resource",
		JWTAudience:                      []string{"static.example.com"},
		ClientCredentialsTokenExpiration: 1 * time.Hour,
	}
	tokenService := createTestTokenService(t, s, cfg)

	// Build a confidential client with client_credentials enabled. We have to
	// generate the secret ourselves so the test can present it back.
	plainSecret := "cc-test-secret-XYZ"
	bcryptHash, err := bcrypt.GenerateFromPassword(
		[]byte(plainSecret), bcrypt.MinCost,
	)
	require.NoError(t, err)
	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientSecret:                string(bcryptHash),
		ClientName:                  "CC Client",
		UserID:                      uuid.New().String(),
		Scopes:                      "read write",
		GrantTypes:                  "client_credentials",
		RedirectURIs:                models.StringArray{},
		ClientType:                  "confidential",
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
	}
	require.NoError(t, s.CreateClient(client))

	token, err := tokenService.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID,
		plainSecret,
		"read",
		nil,
		[]string{"https://mcp.example.com"},
	)
	require.NoError(t, err)
	require.NotNil(t, token)

	// JWT aud reflects the requested resource (not the static JWTAudience).
	claims := decodeJWTClaims(t, token.RawToken)
	aud, ok := claims["aud"].(string)
	require.True(t, ok, "aud must be a string for a single-value resource")
	assert.Equal(t, "https://mcp.example.com", aud)

	// Persisted on the token row for forensic and audit completeness.
	assert.Equal(
		t,
		models.StringArray{"https://mcp.example.com"},
		token.Resource,
	)
}

// TestRefresh_NarrowsResource_Subset confirms a strict subset is accepted.
func TestRefresh_NarrowsResource_Subset(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret-refresh-subset",
		BaseURL:                "http://localhost:8080",
		EnableRefreshTokens:    true,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
	}
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	userID := uuid.New().String()
	now := time.Now()
	authCode := &models.AuthorizationCode{
		UUID:          "test-uuid-" + uuid.New().String(),
		CodeHash:      "hash-" + uuid.New().String(),
		CodePrefix:    "rsrcpfx3",
		ApplicationID: client.ID,
		ClientID:      client.ClientID,
		UserID:        userID,
		RedirectURI:   "https://app.example.com/callback",
		Scopes:        "read write",
		Resource: models.StringArray{
			"https://mcp1.example.com",
			"https://mcp2.example.com",
		},
		ExpiresAt: now.Add(10 * time.Minute),
	}
	require.NoError(t, s.CreateAuthorizationCode(authCode))

	_, refreshToken, _, err := tokenService.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		nil, nil,
		[]string{"https://mcp1.example.com", "https://mcp2.example.com"},
	)
	require.NoError(t, err)

	// Narrow to a single resource from the original grant — must succeed.
	newAccess, _, err := tokenService.RefreshAccessToken(
		context.Background(),
		refreshToken.RawToken,
		client.ClientID,
		"",
		nil,
		[]string{"https://mcp1.example.com"},
	)
	require.NoError(t, err)
	require.NotNil(t, newAccess)

	claims := decodeJWTClaims(t, newAccess.RawToken)
	aud, ok := claims["aud"].(string)
	require.True(t, ok)
	assert.Equal(t, "https://mcp1.example.com", aud)
}
