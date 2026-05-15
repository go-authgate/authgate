// Service-level RFC 8707 coverage. These tests drive TokenService directly
// against a SQLite-backed test store (no Gin router, no HTTP layer) — the
// goal is to pin the resource-binding invariants on the auth-code, refresh,
// and client-credentials grants without paying the cost of full HTTP fixtures.
//
// Fragment-rejection of resource indicators is covered at the validator level
// in internal/util/resource_test.go; HTTP-layer coverage of the auth-code
// flow lives in internal/handlers and the bootstrap-level integration tests.
package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

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

// authorizedDeviceCodeWithResource creates and authorizes a device code that
// records the supplied RFC 8707 resource set, returning the authorized record
// for use in token-exchange tests.
func authorizedDeviceCodeWithResource(
	t *testing.T,
	s *store.Store,
	clientID string,
	resource []string,
) *models.DeviceCode {
	t.Helper()
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(
		s,
		cfg,
		NewNoopAuditService(),
		metrics.NewNoopMetrics(),
		NewClientService(s, NewNoopAuditService(), nil, 0, nil, 0),
	)
	dc, err := deviceService.GenerateDeviceCode(
		context.Background(),
		clientID,
		"read write",
		resource,
	)
	require.NoError(t, err)
	require.NoError(t, deviceService.AuthorizeDeviceCode(
		context.Background(),
		dc.UserCode,
		uuid.New().String(),
		"testuser",
	))
	// Re-load so dc.Resource is hydrated from the DB row that the token
	// exchange path will see.
	loaded, err := deviceService.GetDeviceCode(dc.DeviceCode)
	require.NoError(t, err)
	return loaded
}

// TestDeviceCode_WithResource_PropagatesToAud confirms that a resource bound
// at /oauth/device/code is preserved through to the access token's aud claim
// when the polling /oauth/token request omits its own resource parameter.
func TestDeviceCode_WithResource_PropagatesToAud(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration:   30 * time.Minute,
		PollingInterval:        5,
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret-device-resource",
		BaseURL:                "http://localhost:8080",
		JWTAudience:            []string{"static.example.com"},
		EnableRefreshTokens:    true,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
	}
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	dc := authorizedDeviceCodeWithResource(
		t, s, client.ClientID, []string{"https://mcp.example.com"},
	)

	// No token-time resource → fall back to the granted set on the device code.
	access, refresh, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
		nil,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, access)

	claims := decodeJWTClaims(t, access.RawToken)
	aud, ok := claims["aud"].(string)
	require.True(t, ok, "aud must be a string for a single-value resource")
	assert.Equal(t, "https://mcp.example.com", aud)
	assert.Equal(
		t,
		models.StringArray{"https://mcp.example.com"},
		access.Resource,
		"access-token row must persist the granted resource",
	)

	// Refresh row must also remember the granted resource so future refreshes
	// can re-narrow against the original device-code grant.
	require.NotNil(t, refresh)
	assert.Equal(
		t,
		models.StringArray{"https://mcp.example.com"},
		refresh.Resource,
	)
}

// TestDeviceCode_RejectsResourceSupersetOfGrant exercises RFC 8707 §2.2 on
// the device-code grant: a polling client must not be able to widen the
// audience past what the user authorized at /oauth/device/code.
func TestDeviceCode_RejectsResourceSupersetOfGrant(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret-device-superset",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	dc := authorizedDeviceCodeWithResource(
		t, s, client.ClientID, []string{"https://mcp.example.com"},
	)

	_, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
		nil,
		[]string{"https://forbidden.example.com"},
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTarget)
}

// TestDeviceCode_LinksAuthorizationIDForCascadeRevoke confirms that
// device-code tokens issued after a /device/verify approval inherit the
// AuthorizationID FK on the saved UserAuthorization row. Without this the
// /account/authorizations Revoke button (and the admin "revoke all users
// for this client" action) would not invalidate device-code tokens — the
// docstring claims it does, so the wiring must be present.
func TestDeviceCode_LinksAuthorizationIDForCascadeRevoke(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret-device-cascade",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	dc := authorizedDeviceCodeWithResource(t, s, client.ClientID, nil)

	// Persist a UserAuthorization for the same (user, client) pair — the
	// /device/verify handler does this in production. ExchangeDeviceCode
	// must look it up and thread its ID through to the issued tokens.
	authzService := NewAuthorizationService(s, cfg, NewNoopAuditService(), tokenService,
		NewClientService(s, NewNoopAuditService(), nil, 0, nil, 0))
	ua, err := authzService.SaveUserAuthorization(
		context.Background(),
		dc.UserID, client.ID, client.ClientID,
		dc.Scopes, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, ua)

	access, refresh, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
		nil, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, access)
	require.NotNil(t, refresh)

	// Both access and refresh tokens must carry the same AuthorizationID
	// FK so cascade-revoke takes them out together.
	require.NotNil(t, access.AuthorizationID,
		"device-code access token must be linked to the UserAuthorization row")
	assert.Equal(t, ua.ID, *access.AuthorizationID)
	require.NotNil(t, refresh.AuthorizationID,
		"device-code refresh token must be linked to the UserAuthorization row")
	assert.Equal(t, ua.ID, *refresh.AuthorizationID)
}

// TestClientCredentials_NoResource_SnapshotsJWTAudience confirms the
// audience snapshot semantics: when a token is issued without a per-request
// `resource` parameter but JWT_AUDIENCE is configured, the access-token
// row's Resource column captures the configured audience. This is what lets
// RFC 7662 introspection report `aud` consistently even after operators
// rotate JWT_AUDIENCE — the persisted snapshot stays bound to what the JWT
// was actually signed with.
func TestClientCredentials_NoResource_SnapshotsJWTAudience(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		BaseURL:                          "http://localhost:8080",
		JWTSecret:                        "test-secret-cc-snapshot",
		JWTAudience:                      []string{"snapshot.example.com"},
		ClientCredentialsTokenExpiration: 1 * time.Hour,
	}
	tokenService := createTestTokenService(t, s, cfg)

	plainSecret := "cc-snapshot-secret"
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.MinCost)
	require.NoError(t, err)
	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientSecret:                string(bcryptHash),
		ClientName:                  "CC Snapshot Client",
		UserID:                      uuid.New().String(),
		Scopes:                      "read",
		GrantTypes:                  "client_credentials",
		ClientType:                  "confidential",
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
	}
	require.NoError(t, s.CreateClient(client))

	// Caller does NOT pass `resource` — the JWT will fall back to JWTAudience.
	tok, err := tokenService.IssueClientCredentialsToken(
		context.Background(),
		client.ClientID, plainSecret, "read", nil, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, tok)

	// JWT aud == JWTAudience (single value collapses to string).
	claims := decodeJWTClaims(t, tok.RawToken)
	assert.Equal(t, "snapshot.example.com", claims["aud"])

	// And the row's Resource captures the same snapshot — so introspection
	// later reads the persisted value rather than re-deriving from the live
	// (possibly rotated) config.
	assert.Equal(t, models.StringArray{"snapshot.example.com"}, tok.Resource)
}

// TestDeviceCode_RejectsResourceWhenNoneGranted asserts that a token-time
// resource is rejected when the user authorized a device code without one —
// the empty granted set means "no audience binding" and any resource on
// /oauth/token would be a widening, not a narrowing.
func TestDeviceCode_RejectsResourceWhenNoneGranted(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		JWTExpiration:        1 * time.Hour,
		JWTSecret:            "test-secret-device-empty",
		BaseURL:              "http://localhost:8080",
	}
	tokenService := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	dc := authorizedDeviceCodeWithResource(t, s, client.ClientID, nil)

	_, _, err := tokenService.ExchangeDeviceCode(
		context.Background(),
		dc.DeviceCode,
		client.ClientID,
		nil,
		[]string{"https://mcp.example.com"},
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTarget)
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

// TestRefresh_NoResource_AudienceFrozenAtIssuance is the regression test for
// the Copilot finding: when a grant omits RFC 8707 `resource` and falls back
// to JWT_AUDIENCE, the refresh-token row MUST snapshot that effective
// audience at issuance. Without the snapshot, a later refresh re-derives the
// audience from the live JWT_AUDIENCE config — and rotating that config
// would silently mint refreshed access tokens for a different audience than
// the original grant authorized.
//
// The test verifies two invariants:
//
//  1. After issuance, the refresh-token row's Resource column equals the
//     JWT_AUDIENCE in effect at issuance.
//  2. After rotating JWT_AUDIENCE in config (simulating an operator change
//     made between issuance and refresh), a refresh request that does NOT
//     pass `resource` produces an access token whose `aud` is the ORIGINAL
//     audience, not the rotated value.
func TestRefresh_NoResource_AudienceFrozenAtIssuance(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		JWTExpiration:          1 * time.Hour,
		JWTSecret:              "test-secret-refresh-snapshot",
		BaseURL:                "http://localhost:8080",
		JWTAudience:            []string{"original.example.com"},
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
		CodePrefix:    "snapshtx",
		ApplicationID: client.ID,
		ClientID:      client.ClientID,
		UserID:        userID,
		RedirectURI:   "https://app.example.com/callback",
		Scopes:        "read",
		// Critical: no Resource. The grant relies on JWT_AUDIENCE fallback.
		ExpiresAt: now.Add(10 * time.Minute),
	}
	require.NoError(t, s.CreateAuthorizationCode(authCode))

	accessToken, refreshToken, _, err := tokenService.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		nil, nil,
		nil, // No token-time resource either — pure JWT_AUDIENCE fallback path.
	)
	require.NoError(t, err)
	require.NotNil(t, refreshToken)

	// Invariant 1: both rows captured the JWT_AUDIENCE in effect at issuance.
	assert.Equal(t,
		models.StringArray{"original.example.com"}, accessToken.Resource,
		"access token row must snapshot JWT_AUDIENCE",
	)
	assert.Equal(t,
		models.StringArray{"original.example.com"}, refreshToken.Resource,
		"refresh token row must snapshot JWT_AUDIENCE — without this, "+
			"rotation of JWT_AUDIENCE silently retargets refreshed tokens",
	)

	// Simulate an operator rotating JWT_AUDIENCE while the refresh token is
	// still active. After this point, the live config no longer matches the
	// original grant's audience.
	cfg.JWTAudience = []string{"rotated.example.com"}

	// Invariant 2: refresh without `resource` must produce an access token
	// whose `aud` is the ORIGINAL audience (read from the snapshot on the
	// refresh-token row), NOT the rotated config value.
	newAccess, _, err := tokenService.RefreshAccessToken(
		context.Background(),
		refreshToken.RawToken,
		client.ClientID,
		"",
		nil,
		nil, // refresh without explicit resource
	)
	require.NoError(t, err)
	require.NotNil(t, newAccess)

	claims := decodeJWTClaims(t, newAccess.RawToken)
	aud, ok := claims["aud"].(string)
	require.True(t, ok, "single-value aud should collapse to string")
	assert.Equal(t,
		"original.example.com", aud,
		"refreshed access token must inherit the original-grant audience, "+
			"not the rotated JWT_AUDIENCE config",
	)
	assert.Equal(t,
		models.StringArray{"original.example.com"}, newAccess.Resource,
		"refreshed access token's Resource column also tracks the original snapshot",
	)
}
