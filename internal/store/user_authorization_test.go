package store

import (
	"testing"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestApp creates a minimal OAuthApplication for foreign key references.
func createTestApp(t *testing.T, store *Store) *models.OAuthApplication {
	t.Helper()
	app := &models.OAuthApplication{
		ClientID:         uuid.New().String(),
		ClientSecret:     "secret",
		ClientName:       "Test App",
		UserID:           uuid.New().String(),
		Scopes:           "read write",
		GrantTypes:       "device_code",
		RedirectURIs:     models.StringArray{"http://localhost/callback"},
		EnableDeviceFlow: true,
		Status:           models.ClientStatusActive,
	}
	require.NoError(t, store.CreateClient(app))
	return app
}

func TestGetUserAuthorizationByUUID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestApp(t, store)
		userID := uuid.New().String()
		authUUID := uuid.New().String()

		auth := &models.UserAuthorization{
			UUID:          authUUID,
			UserID:        userID,
			ApplicationID: app.ID,
			ClientID:      app.ClientID,
			Scopes:        "read",
		}
		require.NoError(t, store.UpsertUserAuthorization(auth))

		retrieved, err := store.GetUserAuthorizationByUUID(authUUID, userID)
		require.NoError(t, err)
		assert.Equal(t, authUUID, retrieved.UUID)
		assert.Equal(t, userID, retrieved.UserID)
		assert.Equal(t, "read", retrieved.Scopes)
	})

	t.Run("wrong_user_returns_error", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestApp(t, store)
		userID := uuid.New().String()
		otherUserID := uuid.New().String()
		authUUID := uuid.New().String()

		auth := &models.UserAuthorization{
			UUID:          authUUID,
			UserID:        userID,
			ApplicationID: app.ID,
			ClientID:      app.ClientID,
			Scopes:        "read",
		}
		require.NoError(t, store.UpsertUserAuthorization(auth))

		_, err := store.GetUserAuthorizationByUUID(authUUID, otherUserID)
		assert.Error(t, err)
	})
}

func TestListUserAuthorizations(t *testing.T) {
	t.Run("returns_only_active", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app1 := createTestApp(t, store)
		app2 := createTestApp(t, store)
		userID := uuid.New().String()

		// Create two authorizations
		auth1 := &models.UserAuthorization{
			UUID:          uuid.New().String(),
			UserID:        userID,
			ApplicationID: app1.ID,
			ClientID:      app1.ClientID,
			Scopes:        "read",
		}
		require.NoError(t, store.UpsertUserAuthorization(auth1))

		auth2UUID := uuid.New().String()
		auth2 := &models.UserAuthorization{
			UUID:          auth2UUID,
			UserID:        userID,
			ApplicationID: app2.ID,
			ClientID:      app2.ClientID,
			Scopes:        "write",
		}
		require.NoError(t, store.UpsertUserAuthorization(auth2))

		// Revoke one
		_, err := store.RevokeUserAuthorization(auth2UUID, userID)
		require.NoError(t, err)

		// List should return only the active one
		auths, err := store.ListUserAuthorizations(userID)
		require.NoError(t, err)
		assert.Len(t, auths, 1)
		assert.Equal(t, app1.ClientID, auths[0].ClientID)
	})
}

func TestRevokeUserAuthorization(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestApp(t, store)
		userID := uuid.New().String()
		authUUID := uuid.New().String()

		auth := &models.UserAuthorization{
			UUID:          authUUID,
			UserID:        userID,
			ApplicationID: app.ID,
			ClientID:      app.ClientID,
			Scopes:        "read",
		}
		require.NoError(t, store.UpsertUserAuthorization(auth))

		revoked, err := store.RevokeUserAuthorization(authUUID, userID)
		require.NoError(t, err)
		assert.False(t, revoked.IsActive)

		// Verify it no longer appears in active listing
		auths, err := store.ListUserAuthorizations(userID)
		require.NoError(t, err)
		assert.Empty(t, auths)
	})

	t.Run("wrong_user_returns_error", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestApp(t, store)
		userID := uuid.New().String()
		otherUserID := uuid.New().String()
		authUUID := uuid.New().String()

		auth := &models.UserAuthorization{
			UUID:          authUUID,
			UserID:        userID,
			ApplicationID: app.ID,
			ClientID:      app.ClientID,
			Scopes:        "read",
		}
		require.NoError(t, store.UpsertUserAuthorization(auth))

		_, err := store.RevokeUserAuthorization(authUUID, otherUserID)
		assert.Error(t, err)
	})
}

func TestRevokeAllUserAuthorizationsByClientID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestApp(t, store)
		user1 := uuid.New().String()
		user2 := uuid.New().String()

		// Two users authorized the same client
		for _, uid := range []string{user1, user2} {
			auth := &models.UserAuthorization{
				UUID:          uuid.New().String(),
				UserID:        uid,
				ApplicationID: app.ID,
				ClientID:      app.ClientID,
				Scopes:        "read",
			}
			require.NoError(t, store.UpsertUserAuthorization(auth))
		}

		// Revoke all by client ID
		require.NoError(t, store.RevokeAllUserAuthorizationsByClientID(app.ClientID))

		// Both users should have no active authorizations for this client
		auths1, err := store.ListUserAuthorizations(user1)
		require.NoError(t, err)
		assert.Empty(t, auths1)

		auths2, err := store.ListUserAuthorizations(user2)
		require.NoError(t, err)
		assert.Empty(t, auths2)
	})
}

func TestGetClientAuthorizations(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestApp(t, store)
		user1 := uuid.New().String()
		user2 := uuid.New().String()

		for _, uid := range []string{user1, user2} {
			auth := &models.UserAuthorization{
				UUID:          uuid.New().String(),
				UserID:        uid,
				ApplicationID: app.ID,
				ClientID:      app.ClientID,
				Scopes:        "read write",
			}
			require.NoError(t, store.UpsertUserAuthorization(auth))
		}

		auths, err := store.GetClientAuthorizations(app.ClientID)
		require.NoError(t, err)
		assert.Len(t, auths, 2)

		// Revoke one and verify only one remains
		_, err = store.RevokeUserAuthorization(auths[0].UUID, auths[0].UserID)
		require.NoError(t, err)

		auths, err = store.GetClientAuthorizations(app.ClientID)
		require.NoError(t, err)
		assert.Len(t, auths, 1)
	})
}
