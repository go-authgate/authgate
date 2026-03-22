package store

import (
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// createTestAppForAuthCode creates a minimal OAuthApplication and returns it.
func createTestAppForAuthCode(t *testing.T, s *Store) *models.OAuthApplication {
	t.Helper()
	app := &models.OAuthApplication{
		ClientID:         uuid.New().String(),
		ClientSecret:     "secret",
		ClientName:       "AuthCode Test App",
		UserID:           uuid.New().String(),
		Scopes:           "read write",
		GrantTypes:       "authorization_code",
		EnableDeviceFlow: false,
		Status:           models.ClientStatusActive,
	}
	require.NoError(t, s.CreateClient(app))
	return app
}

func TestGetAuthorizationCodeByHash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestAppForAuthCode(t, store)

		codeHash := "sha256-" + uuid.New().String()
		code := &models.AuthorizationCode{
			UUID:          uuid.New().String(),
			CodeHash:      codeHash,
			CodePrefix:    "abcd1234",
			ApplicationID: app.ID,
			ClientID:      app.ClientID,
			UserID:        uuid.New().String(),
			RedirectURI:   "https://example.com/callback",
			Scopes:        "read write",
			ExpiresAt:     time.Now().Add(10 * time.Minute),
		}
		require.NoError(t, store.CreateAuthorizationCode(code))

		retrieved, err := store.GetAuthorizationCodeByHash(codeHash)
		require.NoError(t, err)
		assert.Equal(t, code.ID, retrieved.ID)
		assert.Equal(t, codeHash, retrieved.CodeHash)
		assert.Equal(t, app.ClientID, retrieved.ClientID)
		assert.Equal(t, code.UserID, retrieved.UserID)
		assert.Equal(t, code.RedirectURI, retrieved.RedirectURI)
		assert.Equal(t, "read write", retrieved.Scopes)
	})

	t.Run("not_found", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		_, err := store.GetAuthorizationCodeByHash("nonexistent-hash")
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}

func TestMarkAuthorizationCodeUsed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestAppForAuthCode(t, store)

		code := &models.AuthorizationCode{
			UUID:          uuid.New().String(),
			CodeHash:      "hash-" + uuid.New().String(),
			CodePrefix:    "efgh5678",
			ApplicationID: app.ID,
			ClientID:      app.ClientID,
			UserID:        uuid.New().String(),
			RedirectURI:   "https://example.com/cb",
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(10 * time.Minute),
		}
		require.NoError(t, store.CreateAuthorizationCode(code))

		require.NoError(t, store.MarkAuthorizationCodeUsed(code.ID))

		retrieved, err := store.GetAuthorizationCodeByHash(code.CodeHash)
		require.NoError(t, err)
		assert.NotNil(t, retrieved.UsedAt)
		assert.True(t, retrieved.IsUsed())
	})

	t.Run("already_used_returns_error", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		app := createTestAppForAuthCode(t, store)

		code := &models.AuthorizationCode{
			UUID:          uuid.New().String(),
			CodeHash:      "hash-" + uuid.New().String(),
			CodePrefix:    "ijkl9012",
			ApplicationID: app.ID,
			ClientID:      app.ClientID,
			UserID:        uuid.New().String(),
			RedirectURI:   "https://example.com/cb",
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(10 * time.Minute),
		}
		require.NoError(t, store.CreateAuthorizationCode(code))

		require.NoError(t, store.MarkAuthorizationCodeUsed(code.ID))

		err := store.MarkAuthorizationCodeUsed(code.ID)
		require.ErrorIs(t, err, ErrAuthCodeAlreadyUsed)
	})
}
