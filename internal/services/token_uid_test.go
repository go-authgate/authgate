package services

import (
	"context"
	"testing"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// seedUserForAuthorizedDeviceCode recovers the post-authorize UserID by
// re-reading the device code (createAuthorizedDeviceCode returns a
// pre-authorize snapshot), seeds a User row at that ID with a deterministic
// username, and mutates dc.UserID in place. dc.DeviceCode (gorm:"-")
// is preserved so subsequent ExchangeDeviceCode calls still resolve.
func seedUserForAuthorizedDeviceCode(
	t *testing.T,
	s *store.Store,
	dc *models.DeviceCode,
	username string,
) {
	t.Helper()
	fresh, err := s.GetDeviceCodeByUserCode(dc.UserCode)
	require.NoError(t, err)
	require.NotEmpty(t, fresh.UserID, "device code must be authorized before seeding user")
	dc.UserID = fresh.UserID
	require.NoError(t, s.CreateUser(&models.User{
		ID:       fresh.UserID,
		Username: username,
		Email:    username + "@example.com",
		IsActive: true,
	}))
}

func TestAuthCodeFlow_EmitsUidClaim(t *testing.T) {
	t.Run("auth_code", func(t *testing.T) {
		s := setupTestStore(t)
		cfg := domainTestConfig("")
		svc := createTestTokenService(t, s, cfg)

		user := &models.User{
			ID:       uuid.New().String(),
			Username: "alice",
			Email:    "alice@example.com",
			IsActive: true,
		}
		require.NoError(t, s.CreateUser(user))
		client := createTestClient(t, s, true)
		authCode := createTestAuthCodeRecord(t, s, client, user.ID)

		access, refresh, _, err := svc.ExchangeAuthorizationCode(
			context.Background(), authCode, nil, nil,
		)
		require.NoError(t, err)

		assertPrivateClaim(t, cfg, access.RawToken, "uid", "alice")
		assertPrivateClaim(t, cfg, refresh.RawToken, "uid", "alice")
	})

	t.Run("device_code", func(t *testing.T) {
		s := setupTestStore(t)
		cfg := domainTestConfig("")
		svc := createTestTokenService(t, s, cfg)

		client := createTestClient(t, s, true)
		dc := createAuthorizedDeviceCode(t, s, client.ClientID)
		seedUserForAuthorizedDeviceCode(t, s, dc, "bob")

		access, refresh, err := svc.ExchangeDeviceCode(
			context.Background(), dc.DeviceCode, client.ClientID, nil,
		)
		require.NoError(t, err)

		assertPrivateClaim(t, cfg, access.RawToken, "uid", "bob")
		assertPrivateClaim(t, cfg, refresh.RawToken, "uid", "bob")
	})
}

// TestClientCredentialsFlow_OmitsUidClaim diverges intentionally from
// TestClientCredentialsFlow_DomainClaim: client_credentials has no real user,
// so uid is suppressed while domain is still emitted.
func TestClientCredentialsFlow_OmitsUidClaim(t *testing.T) {
	s := setupTestStore(t)
	cfg := domainTestConfig("oa")
	svc := createTestTokenService(t, s, cfg)

	client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

	tok, err := svc.IssueClientCredentialsToken(
		context.Background(), client.ClientID, plainSecret, "", nil,
	)
	require.NoError(t, err)

	assertPrivateClaim(t, cfg, tok.RawToken, "uid", "")
	// Sanity: domain still emitted, confirming server-claim composition reached
	// the JWT — the absence above is targeted at uid only.
	assertPrivateClaim(t, cfg, tok.RawToken, "domain", "oa")
}

// TestRefresh_ReResolvesUidAfterUsernameChange pins live re-resolution: an
// admin rename between issuance and refresh must propagate to the next
// refreshed token, mirroring the JWT_DOMAIN re-resolution pattern.
func TestRefresh_ReResolvesUidAfterUsernameChange(t *testing.T) {
	s := setupTestStore(t)
	cfg := domainTestConfig("")
	cfg.EnableTokenRotation = true // rotation produces a fresh refresh JWT to decode
	svc := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)
	seedUserForAuthorizedDeviceCode(t, s, dc, "alice")

	_, refresh, err := svc.ExchangeDeviceCode(
		context.Background(), dc.DeviceCode, client.ClientID, nil,
	)
	require.NoError(t, err)
	assertPrivateClaim(t, cfg, refresh.RawToken, "uid", "alice")

	user, err := s.GetUserByID(dc.UserID)
	require.NoError(t, err)
	user.Username = "alice2"
	require.NoError(t, s.UpdateUser(user))

	newAccess, newRefresh, err := svc.RefreshAccessToken(
		context.Background(), refresh.RawToken, client.ClientID, "read write", nil,
	)
	require.NoError(t, err)

	assertPrivateClaim(t, cfg, newAccess.RawToken, "uid", "alice2")
	assertPrivateClaim(t, cfg, newRefresh.RawToken, "uid", "alice2")
}

// TestUidClaim_OmittedWhenUserLookupFails pins the "log + omit, never fail"
// contract: a missing User row must leave issuance succeeding with the claim
// absent rather than carrying a stale, empty, or fabricated value.
func TestUidClaim_OmittedWhenUserLookupFails(t *testing.T) {
	s := setupTestStore(t)
	cfg := domainTestConfig("")
	svc := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	missingUserID := uuid.New().String()
	authCode := createTestAuthCodeRecord(t, s, client, missingUserID)

	access, refresh, _, err := svc.ExchangeAuthorizationCode(
		context.Background(), authCode, nil, nil,
	)
	require.NoError(t, err, "issuance must not fail when uid lookup misses")

	assertPrivateClaim(t, cfg, access.RawToken, "uid", "")
	assertPrivateClaim(t, cfg, refresh.RawToken, "uid", "")
}
