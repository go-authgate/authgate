package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
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

func newCachedTokenService(
	t *testing.T,
) (*TokenService, *store.Store, *cache.MemoryCache[models.AccessToken]) {
	t.Helper()
	return newCachedTokenServiceWithConfig(t, &config.Config{
		JWTExpiration:                    1 * time.Hour,
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		JWTSecret:                        "test-secret",
		BaseURL:                          "http://localhost:8080",
		TokenCacheEnabled:                true,
		TokenCacheTTL:                    5 * time.Minute,
	})
}

func newCachedTokenServiceWithConfig(
	t *testing.T,
	cfg *config.Config,
) (*TokenService, *store.Store, *cache.MemoryCache[models.AccessToken]) {
	t.Helper()
	s := setupTestStore(t)
	memCache := cache.NewMemoryCache[models.AccessToken]()
	localProvider, err := token.NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	clientService := NewClientService(s, nil, nil, 0, nil, 0)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics(), clientService)
	svc := NewTokenService(
		s,
		cfg,
		deviceService,
		localProvider,
		nil,
		metrics.NewNoopMetrics(),
		memCache,
		clientService,
	)
	return svc, s, memCache
}

func TestValidateToken_CacheHit(t *testing.T) {
	svc, s, memCache := newCachedTokenService(t)
	ctx := context.Background()

	// Generate a real JWT token
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	// Store token in DB
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// First call: cache miss, loads from DB
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)

	// Verify token is now in cache
	cached, err := memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	require.NoError(t, err)
	assert.Equal(t, tok.ID, cached.ID)

	// Second call: should succeed (hits cache)
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)
}

func TestValidateToken_CacheInvalidatedOnRevoke(t *testing.T) {
	svc, s, memCache := newCachedTokenService(t)
	ctx := context.Background()

	// Generate a real JWT token
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	// Store token in DB
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// Validate to populate cache
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)

	// Verify cache is populated
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	require.NoError(t, err)

	// Revoke token
	err = svc.RevokeToken(result.TokenString)
	require.NoError(t, err)

	// Verify cache is invalidated
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	assert.Error(t, err, "cache should be invalidated after revocation")
}

func TestValidateToken_CacheInvalidatedOnDisable(t *testing.T) {
	svc, s, memCache := newCachedTokenService(t)
	ctx := context.Background()

	// Generate a real JWT token
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	// Store token in DB
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// Validate to populate cache
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)

	// Disable token
	err = svc.DisableToken(ctx, tok.ID, "admin")
	require.NoError(t, err)

	// Verify cache is invalidated
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	assert.Error(t, err, "cache should be invalidated after disable")
}

func TestValidateToken_NoopCache(t *testing.T) {
	// Test that everything works when cache is a no-op (disabled)
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:                    1 * time.Hour,
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		JWTSecret:                        "test-secret",
		BaseURL:                          "http://localhost:8080",
	}
	localProvider, err := token.NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	clientService := NewClientService(s, nil, nil, 0, nil, 0)
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics(), clientService)
	svc := NewTokenService(
		s, cfg, deviceService, localProvider, nil, metrics.NewNoopMetrics(),
		cache.NewNoopCache[models.AccessToken](), clientService,
	)

	ctx := context.Background()
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// Should work without cache
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)

	// Revoke should also work without cache
	err = svc.RevokeToken(result.TokenString)
	require.NoError(t, err)
}

func TestValidateToken_CacheExpiredTokenRejected(t *testing.T) {
	svc, s, _ := newCachedTokenService(t)
	ctx := context.Background()

	// Generate a real JWT token
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	// Store token with past expiration
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     time.Now().Add(-1 * time.Hour), // Already expired in DB
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// Even if token is cached, expired tokens should be rejected
	_, err = svc.ValidateToken(ctx, result.TokenString)
	assert.Error(t, err, "expired token should be rejected even if cached")
}

func TestRevokeTokenByStatus_CacheInvalidated(t *testing.T) {
	svc, s, memCache := newCachedTokenService(t)
	ctx := context.Background()

	// Generate a real JWT token
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	// Store token in DB
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// Populate cache
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)

	// Verify cache is populated
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	require.NoError(t, err)

	// Revoke by status
	err = svc.RevokeTokenByStatus(tok.ID)
	require.NoError(t, err)

	// Verify cache is invalidated
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	assert.Error(t, err, "cache should be invalidated after RevokeTokenByStatus")
}

func TestRevokeTokenByID_CacheInvalidated(t *testing.T) {
	svc, s, memCache := newCachedTokenService(t)
	ctx := context.Background()

	// Generate a real JWT token
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	// Store token in DB
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// Validate to populate cache
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)

	// Verify cache is populated
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	require.NoError(t, err)

	// Revoke by ID
	err = svc.RevokeTokenByID(ctx, tok.ID, "admin")
	require.NoError(t, err)

	// Verify cache is invalidated
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	assert.Error(t, err, "cache should be invalidated after RevokeTokenByID")
}

func TestEnableToken_CacheInvalidated(t *testing.T) {
	svc, s, memCache := newCachedTokenService(t)
	ctx := context.Background()

	// Generate a real JWT token
	result, err := svc.tokenProvider.GenerateToken(ctx, "test-user", "test-client", "read")
	require.NoError(t, err)

	// Store token in DB
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "test-user",
		ClientID:      "test-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	err = s.CreateAccessToken(tok)
	require.NoError(t, err)

	// Validate to populate cache
	_, err = svc.ValidateToken(ctx, result.TokenString)
	require.NoError(t, err)

	// Disable token — cache should be invalidated
	err = svc.DisableToken(ctx, tok.ID, "admin")
	require.NoError(t, err)
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	require.Error(t, err, "cache should be invalidated after disable")

	// Re-enable token — cache should be invalidated again (stale disabled entry evicted)
	err = svc.EnableToken(ctx, tok.ID, "admin")
	require.NoError(t, err)
	_, err = memCache.Get(ctx, util.SHA256Hex(result.TokenString))
	assert.Error(t, err, "cache should be invalidated after enable")
}

func TestRevokeAllUserTokens_CacheInvalidated(t *testing.T) {
	svc, s, memCache := newCachedTokenService(t)
	ctx := context.Background()

	userID := "test-user-bulk"

	// Generate two tokens for the same user
	result1, err := svc.tokenProvider.GenerateToken(ctx, userID, "client-1", "read")
	require.NoError(t, err)
	result2, err := svc.tokenProvider.GenerateToken(ctx, userID, "client-2", "write")
	require.NoError(t, err)

	tok1 := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result1.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        userID,
		ClientID:      "client-1",
		Scopes:        "read",
		ExpiresAt:     result1.ExpiresAt,
	}
	tok2 := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result2.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        userID,
		ClientID:      "client-2",
		Scopes:        "write",
		ExpiresAt:     result2.ExpiresAt,
	}
	require.NoError(t, s.CreateAccessToken(tok1))
	require.NoError(t, s.CreateAccessToken(tok2))

	// Validate both to populate cache
	_, err = svc.ValidateToken(ctx, result1.TokenString)
	require.NoError(t, err)
	_, err = svc.ValidateToken(ctx, result2.TokenString)
	require.NoError(t, err)

	// Verify both are cached
	_, err = memCache.Get(ctx, util.SHA256Hex(result1.TokenString))
	require.NoError(t, err)
	_, err = memCache.Get(ctx, util.SHA256Hex(result2.TokenString))
	require.NoError(t, err)

	// Revoke all tokens for the user
	err = svc.RevokeAllUserTokens(userID)
	require.NoError(t, err)

	// Verify both cache entries are invalidated
	_, err = memCache.Get(ctx, util.SHA256Hex(result1.TokenString))
	require.Error(t, err, "token 1 cache should be invalidated after RevokeAllUserTokens")
	_, err = memCache.Get(ctx, util.SHA256Hex(result2.TokenString))
	assert.Error(t, err, "token 2 cache should be invalidated after RevokeAllUserTokens")
}

func TestRefreshAccessToken_RotationMode_CacheInvalidated(t *testing.T) {
	cfg := &config.Config{
		DeviceCodeExpiration:   30 * time.Minute,
		PollingInterval:        5,
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret",
		BaseURL:                "http://localhost:8080",
		EnableRefreshTokens:    true,
		EnableTokenRotation:    true,
		RefreshTokenExpiration: 720 * time.Hour,
		TokenCacheEnabled:      true,
		TokenCacheTTL:          5 * time.Minute,
	}
	svc, s, memCache := newCachedTokenServiceWithConfig(t, cfg)
	ctx := context.Background()

	// Create client and get initial tokens via device flow
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	_, initialRefresh, err := svc.ExchangeDeviceCode(ctx, dc.DeviceCode, client.ClientID)
	require.NoError(t, err)
	require.NotNil(t, initialRefresh)

	// Populate cache with the refresh token hash by calling getAccessTokenByHash
	oldHash := util.SHA256Hex(initialRefresh.RawToken)
	_, err = memCache.GetWithFetch(ctx, oldHash, cfg.TokenCacheTTL,
		func(ctx context.Context, key string) (models.AccessToken, error) {
			tok, err := s.GetAccessTokenByHash(key)
			if err != nil {
				return models.AccessToken{}, err
			}
			return *tok, nil
		},
	)
	require.NoError(t, err)

	// Verify cache is populated
	_, err = memCache.Get(ctx, oldHash)
	require.NoError(t, err)

	// Refresh with rotation — old refresh token should be revoked and cache invalidated
	_, newRefresh, err := svc.RefreshAccessToken(
		ctx, initialRefresh.RawToken, client.ClientID, "read write",
	)
	require.NoError(t, err)
	require.NotNil(t, newRefresh)

	// Verify old refresh token cache entry is evicted
	_, err = memCache.Get(ctx, oldHash)
	assert.Error(t, err, "old refresh token should be evicted from cache after rotation")
}

func TestRevokeTokenFamily_CacheInvalidated(t *testing.T) {
	cfg := &config.Config{
		DeviceCodeExpiration:   30 * time.Minute,
		PollingInterval:        5,
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret",
		BaseURL:                "http://localhost:8080",
		EnableRefreshTokens:    true,
		EnableTokenRotation:    true,
		RefreshTokenExpiration: 720 * time.Hour,
		TokenCacheEnabled:      true,
		TokenCacheTTL:          5 * time.Minute,
	}
	svc, s, memCache := newCachedTokenServiceWithConfig(t, cfg)
	ctx := context.Background()

	// Create client and get initial tokens via device flow
	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	initialAccess, initialRefresh, err := svc.ExchangeDeviceCode(
		ctx, dc.DeviceCode, client.ClientID,
	)
	require.NoError(t, err)
	require.NotNil(t, initialRefresh)

	// Populate cache with initial access token
	accessHash := util.SHA256Hex(initialAccess.RawToken)
	_, err = svc.ValidateToken(ctx, initialAccess.RawToken)
	require.NoError(t, err)
	_, err = memCache.Get(ctx, accessHash)
	require.NoError(t, err, "initial access token should be cached")

	// Rotate: first refresh succeeds, old refresh token gets revoked
	newAccess, newRefresh, err := svc.RefreshAccessToken(
		ctx, initialRefresh.RawToken, client.ClientID, "read write",
	)
	require.NoError(t, err)
	require.NotNil(t, newRefresh)

	// Populate cache with new access token
	newAccessHash := util.SHA256Hex(newAccess.RawToken)
	_, err = svc.ValidateToken(ctx, newAccess.RawToken)
	require.NoError(t, err)
	_, err = memCache.Get(ctx, newAccessHash)
	require.NoError(t, err, "new access token should be cached")

	// Replay attack: reuse old (revoked) refresh token → triggers family revocation
	_, _, err = svc.RefreshAccessToken(
		ctx, initialRefresh.RawToken, client.ClientID, "read write",
	)
	require.Error(t, err, "replay should fail")

	// Verify new access token cache entry is evicted (family revocation)
	_, err = memCache.Get(ctx, newAccessHash)
	assert.Error(t, err, "new access token should be evicted from cache after family revocation")
}
