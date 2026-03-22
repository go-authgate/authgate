package store

import (
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAuthorizationCodeByHash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		codeHash := "sha256-" + uuid.New().String()
		code := &models.AuthorizationCode{
			UUID:          uuid.New().String(),
			CodeHash:      codeHash,
			CodePrefix:    "abcd1234",
			ApplicationID: 1,
			ClientID:      uuid.New().String(),
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
		assert.Equal(t, code.ClientID, retrieved.ClientID)
		assert.Equal(t, code.UserID, retrieved.UserID)
		assert.Equal(t, code.RedirectURI, retrieved.RedirectURI)
		assert.Equal(t, "read write", retrieved.Scopes)
	})

	t.Run("not_found", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		_, err := store.GetAuthorizationCodeByHash("nonexistent-hash")
		assert.Error(t, err)
	})
}

func TestMarkAuthorizationCodeUsed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		code := &models.AuthorizationCode{
			UUID:          uuid.New().String(),
			CodeHash:      "hash-" + uuid.New().String(),
			CodePrefix:    "efgh5678",
			ApplicationID: 1,
			ClientID:      uuid.New().String(),
			UserID:        uuid.New().String(),
			RedirectURI:   "https://example.com/cb",
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(10 * time.Minute),
		}
		require.NoError(t, store.CreateAuthorizationCode(code))

		// Mark as used
		require.NoError(t, store.MarkAuthorizationCodeUsed(code.ID))

		// Verify UsedAt is set
		retrieved, err := store.GetAuthorizationCodeByHash(code.CodeHash)
		require.NoError(t, err)
		assert.NotNil(t, retrieved.UsedAt)
		assert.True(t, retrieved.IsUsed())
	})

	t.Run("already_used_returns_error", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		code := &models.AuthorizationCode{
			UUID:          uuid.New().String(),
			CodeHash:      "hash-" + uuid.New().String(),
			CodePrefix:    "ijkl9012",
			ApplicationID: 1,
			ClientID:      uuid.New().String(),
			UserID:        uuid.New().String(),
			RedirectURI:   "https://example.com/cb",
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(10 * time.Minute),
		}
		require.NoError(t, store.CreateAuthorizationCode(code))

		// First call succeeds
		require.NoError(t, store.MarkAuthorizationCodeUsed(code.ID))

		// Second call returns ErrAuthCodeAlreadyUsed
		err := store.MarkAuthorizationCodeUsed(code.ID)
		require.ErrorIs(t, err, ErrAuthCodeAlreadyUsed)
	})
}
