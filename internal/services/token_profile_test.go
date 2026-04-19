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
)

// createTestClientWithProfile creates an active client seeded with the given
// TokenProfile. The test helpers in device_test.go only support the common path,
// so this mirrors them for token-profile-specific tests.
func createTestClientWithProfile(
	t *testing.T,
	svc *TokenService,
	profile string,
) *models.OAuthApplication {
	t.Helper()
	client := &models.OAuthApplication{
		ClientID:         uuid.New().String(),
		ClientSecret:     "secret",
		ClientName:       "Profile Test Client",
		UserID:           uuid.New().String(),
		Scopes:           "read write",
		GrantTypes:       "device_code",
		RedirectURIs:     models.StringArray{},
		EnableDeviceFlow: true,
		Status:           models.ClientStatusActive,
		TokenProfile:     profile,
	}
	require.NoError(t, svc.store.CreateClient(client))
	return client
}

// configWithTokenProfiles builds a *config.Config that defines the three named
// profiles with distinctive TTL values so tests can assert which one was picked.
func configWithTokenProfiles() *config.Config {
	return &config.Config{
		JWTSecret:                        "test-secret-that-is-at-least-32b",
		JWTExpiration:                    10 * time.Hour, // standard default
		RefreshTokenExpiration:           720 * time.Hour,
		ClientCredentialsTokenExpiration: time.Hour,
		BaseURL:                          "http://localhost:8080",
		DeviceCodeExpiration:             30 * time.Minute,
		PollingInterval:                  5,
		TokenProfiles: map[string]config.TokenProfile{
			models.TokenProfileShort: {
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
			},
			models.TokenProfileStandard: {
				AccessTokenTTL:  10 * time.Hour,
				RefreshTokenTTL: 720 * time.Hour,
			},
			models.TokenProfileLong: {
				AccessTokenTTL:  24 * time.Hour,
				RefreshTokenTTL: 2160 * time.Hour,
			},
		},
	}
}

func TestResolveClientTTL_UsesClientProfile(t *testing.T) {
	cfg := configWithTokenProfiles()
	s := setupTestStore(t)
	svc := createTestTokenService(t, s, cfg)

	shortClient := createTestClientWithProfile(t, svc, models.TokenProfileShort)
	longClient := createTestClientWithProfile(t, svc, models.TokenProfileLong)

	ctx := context.Background()
	accessTTL, refreshTTL := svc.resolveClientTTL(ctx, shortClient.ClientID)
	assert.Equal(t, 15*time.Minute, accessTTL, "short profile access TTL")
	assert.Equal(t, 24*time.Hour, refreshTTL, "short profile refresh TTL")

	accessTTL, refreshTTL = svc.resolveClientTTL(ctx, longClient.ClientID)
	assert.Equal(t, 24*time.Hour, accessTTL, "long profile access TTL")
	assert.Equal(t, 2160*time.Hour, refreshTTL, "long profile refresh TTL")
}

func TestResolveClientTTL_EmptyProfileDefaultsToStandard(t *testing.T) {
	cfg := configWithTokenProfiles()
	s := setupTestStore(t)
	svc := createTestTokenService(t, s, cfg)

	// A client with TokenProfile == "" (e.g. pre-migration row) must resolve
	// to the "standard" preset, matching what the GORM default would apply.
	client := createTestClientWithProfile(t, svc, "")

	accessTTL, refreshTTL := svc.resolveClientTTL(context.Background(), client.ClientID)
	standard := cfg.TokenProfiles[models.TokenProfileStandard]
	assert.Equal(t, standard.AccessTokenTTL, accessTTL)
	assert.Equal(t, standard.RefreshTokenTTL, refreshTTL)
}

func TestResolveClientTTL_UnknownClientFallsBackToZero(t *testing.T) {
	cfg := configWithTokenProfiles()
	s := setupTestStore(t)
	svc := createTestTokenService(t, s, cfg)

	// Returning 0,0 tells the provider to use its config default — a safe
	// fallback for an issuance path with an unknown or deleted client.
	accessTTL, refreshTTL := svc.resolveClientTTL(context.Background(), "nonexistent")
	assert.Equal(t, time.Duration(0), accessTTL)
	assert.Equal(t, time.Duration(0), refreshTTL)
}

func TestExchangeDeviceCode_HonorsShortProfile(t *testing.T) {
	cfg := configWithTokenProfiles()
	s := setupTestStore(t)
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClientWithProfile(t, tokenService, models.TokenProfileShort)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)

	access, refresh, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
	)
	require.NoError(t, err)

	// The short profile is 15m access / 24h refresh — check within tolerance.
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), access.ExpiresAt, 5*time.Second)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), refresh.ExpiresAt, 5*time.Second)
}

func TestResolveClientTTL_ReflectsLatestProfileFromStore(t *testing.T) {
	// The refresh-token path re-calls resolveClientTTL at refresh time so that
	// a profile change takes effect on the next issuance. This test bypasses
	// the clientService cache (by using a fresh service with zero cache TTL
	// via a cleared cache) to assert the resolver reads the up-to-date row.
	cfg := configWithTokenProfiles()
	s := setupTestStore(t)
	svc := createTestTokenService(t, s, cfg)

	client := createTestClientWithProfile(t, svc, models.TokenProfileStandard)

	accessTTL, _ := svc.resolveClientTTL(context.Background(), client.ClientID)
	assert.Equal(t, 10*time.Hour, accessTTL, "initial profile is standard")

	// Update profile and invalidate the cache the way UpdateClient would.
	client.TokenProfile = models.TokenProfileShort
	require.NoError(t, s.UpdateClient(client))
	svc.clientService.invalidateClientCache(context.Background(), client.ClientID)

	accessTTL, _ = svc.resolveClientTTL(context.Background(), client.ClientID)
	assert.Equal(
		t,
		15*time.Minute,
		accessTTL,
		"profile change is picked up after cache invalidation",
	)
}
