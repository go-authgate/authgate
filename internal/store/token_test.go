package store

import (
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestToken is a helper that builds a minimal AccessToken with sensible defaults.
func createTestToken(userID, clientID string) *models.AccessToken {
	return &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(uuid.New().String()),
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        userID,
		ClientID:      clientID,
		Scopes:        "read write",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
}

// createTestClient is a helper that creates an OAuthApplication in the store.
func createTestClient(t *testing.T, s *Store, clientID, clientName string) {
	t.Helper()
	client := &models.OAuthApplication{
		ClientID:         clientID,
		ClientName:       clientName,
		UserID:           uuid.New().String(),
		Scopes:           "read write",
		GrantTypes:       "device_code",
		EnableDeviceFlow: true,
		Status:           models.ClientStatusActive,
	}
	require.NoError(t, s.CreateClient(client))
}

func TestGetTokensByUserIDPaginated(t *testing.T) {
	t.Run("BasicPagination", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		userID := uuid.New().String()
		clientID := uuid.New().String()

		createTestClient(t, store, clientID, "Test App")

		// Create 5 tokens
		for range 5 {
			tok := createTestToken(userID, clientID)
			require.NoError(t, store.CreateAccessToken(tok))
		}

		// First page, 2 per page
		tokens, pagination, err := store.GetTokensByUserIDPaginated(userID, PaginationParams{
			Page:     1,
			PageSize: 2,
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
		assert.Equal(t, int64(5), pagination.Total)
		assert.Equal(t, 3, pagination.TotalPages)
		assert.Equal(t, 1, pagination.CurrentPage)
		assert.False(t, pagination.HasPrev)
		assert.True(t, pagination.HasNext)

		// Last page should have 1 token
		tokens, pagination, err = store.GetTokensByUserIDPaginated(userID, PaginationParams{
			Page:     3,
			PageSize: 2,
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
		assert.True(t, pagination.HasPrev)
		assert.False(t, pagination.HasNext)
	})

	t.Run("SearchByClientName", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		userID := uuid.New().String()

		clientA := uuid.New().String()
		clientB := uuid.New().String()
		createTestClient(t, store, clientA, "Alpha Dashboard")
		createTestClient(t, store, clientB, "Beta Service")

		// 2 tokens for Alpha, 1 for Beta
		for range 2 {
			tok := createTestToken(userID, clientA)
			require.NoError(t, store.CreateAccessToken(tok))
		}
		tokB := createTestToken(userID, clientB)
		require.NoError(t, store.CreateAccessToken(tokB))

		// Search for "Alpha" should match only client A tokens
		tokens, pagination, err := store.GetTokensByUserIDPaginated(userID, PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "Alpha",
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
		assert.Equal(t, int64(2), pagination.Total)

		// Search for "Beta" should match only client B tokens
		tokens, pagination, err = store.GetTokensByUserIDPaginated(userID, PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "Beta",
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
		assert.Equal(t, int64(1), pagination.Total)
	})

	t.Run("SearchByScopes", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		userID := uuid.New().String()
		clientID := uuid.New().String()
		createTestClient(t, store, clientID, "My App")

		tok1 := createTestToken(userID, clientID)
		tok1.Scopes = "admin:full"
		require.NoError(t, store.CreateAccessToken(tok1))

		tok2 := createTestToken(userID, clientID)
		tok2.Scopes = "read"
		require.NoError(t, store.CreateAccessToken(tok2))

		// Searching for "admin" should match only the first token's scope
		tokens, pagination, err := store.GetTokensByUserIDPaginated(userID, PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "admin",
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
		assert.Equal(t, int64(1), pagination.Total)
		assert.Equal(t, "admin:full", tokens[0].Scopes)
	})

	t.Run("SearchNoMatch", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		userID := uuid.New().String()
		clientID := uuid.New().String()
		createTestClient(t, store, clientID, "Some App")

		tok := createTestToken(userID, clientID)
		require.NoError(t, store.CreateAccessToken(tok))

		tokens, pagination, err := store.GetTokensByUserIDPaginated(userID, PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "nonexistent",
		})
		require.NoError(t, err)
		assert.Empty(t, tokens)
		assert.Equal(t, int64(0), pagination.Total)
		assert.Equal(t, 0, pagination.TotalPages)
	})

	t.Run("EmptyResult", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		userID := uuid.New().String()

		tokens, pagination, err := store.GetTokensByUserIDPaginated(userID, PaginationParams{
			Page:     1,
			PageSize: 10,
		})
		require.NoError(t, err)
		assert.Empty(t, tokens)
		assert.Equal(t, int64(0), pagination.Total)
		assert.Equal(t, 0, pagination.TotalPages)
	})

	t.Run("DoesNotReturnOtherUsersTokens", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		user1 := uuid.New().String()
		user2 := uuid.New().String()
		clientID := uuid.New().String()
		createTestClient(t, store, clientID, "Shared App")

		// Create tokens for two different users
		for range 3 {
			require.NoError(t, store.CreateAccessToken(createTestToken(user1, clientID)))
		}
		for range 2 {
			require.NoError(t, store.CreateAccessToken(createTestToken(user2, clientID)))
		}

		tokens, pagination, err := store.GetTokensByUserIDPaginated(user1, PaginationParams{
			Page:     1,
			PageSize: 10,
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 3)
		assert.Equal(t, int64(3), pagination.Total)

		// Verify all returned tokens belong to user1
		for _, tok := range tokens {
			assert.Equal(t, user1, tok.UserID)
		}
	})
}

func TestRevokeToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		tok := createTestToken(uuid.New().String(), uuid.New().String())
		require.NoError(t, store.CreateAccessToken(tok))

		// Verify token exists
		_, err := store.GetAccessTokenByID(tok.ID)
		require.NoError(t, err)

		// Revoke (hard delete)
		err = store.RevokeToken(tok.ID)
		require.NoError(t, err)

		// Verify token is gone
		_, err = store.GetAccessTokenByID(tok.ID)
		assert.Error(t, err)
	})

	t.Run("NonExistentToken", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		// RevokeToken uses gorm Delete which does not error on missing rows
		err := store.RevokeToken("does-not-exist")
		assert.NoError(t, err)
	})
}

func TestRevokeTokensByAuthorizationID(t *testing.T) {
	t.Run("RevokesMatchingTokens", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		userID := uuid.New().String()
		clientID := uuid.New().String()
		authID := uint(42)
		otherAuthID := uint(99)

		// Create 2 active tokens linked to authID
		for range 2 {
			tok := createTestToken(userID, clientID)
			tok.AuthorizationID = &authID
			require.NoError(t, store.CreateAccessToken(tok))
		}

		// Create 1 active token linked to a different authorization
		tokOther := createTestToken(userID, clientID)
		tokOther.AuthorizationID = &otherAuthID
		require.NoError(t, store.CreateAccessToken(tokOther))

		// Create 1 already-revoked token linked to authID (should not change)
		tokRevoked := createTestToken(userID, clientID)
		tokRevoked.AuthorizationID = &authID
		tokRevoked.Status = models.TokenStatusRevoked
		require.NoError(t, store.CreateAccessToken(tokRevoked))

		err := store.RevokeTokensByAuthorizationID(authID)
		require.NoError(t, err)

		// All tokens for authID should now be revoked
		allTokens, err := store.GetTokensByUserID(userID)
		require.NoError(t, err)

		for _, tok := range allTokens {
			if tok.AuthorizationID != nil && *tok.AuthorizationID == authID {
				assert.Equal(t, models.TokenStatusRevoked, tok.Status,
					"token %s linked to authID %d should be revoked", tok.ID, authID)
			}
		}

		// Token linked to otherAuthID should still be active
		other, err := store.GetAccessTokenByID(tokOther.ID)
		require.NoError(t, err)
		assert.Equal(t, models.TokenStatusActive, other.Status)
	})

	t.Run("NoMatchingTokens", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		// Revoking with a non-existent authorization ID should not error
		err := store.RevokeTokensByAuthorizationID(uint(12345))
		assert.NoError(t, err)
	})
}

func TestRevokeAllActiveTokensByClientID(t *testing.T) {
	t.Run("RevokesActiveTokensAndReturnsCount", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		clientID := uuid.New().String()
		otherClientID := uuid.New().String()
		userID := uuid.New().String()

		// Create 3 active tokens for the target client
		for range 3 {
			tok := createTestToken(userID, clientID)
			require.NoError(t, store.CreateAccessToken(tok))
		}

		// Create 1 already-revoked token for the target client
		revoked := createTestToken(userID, clientID)
		revoked.Status = models.TokenStatusRevoked
		require.NoError(t, store.CreateAccessToken(revoked))

		// Create 1 disabled token for the target client
		disabled := createTestToken(userID, clientID)
		disabled.Status = models.TokenStatusDisabled
		require.NoError(t, store.CreateAccessToken(disabled))

		// Create 2 active tokens for a different client
		for range 2 {
			tok := createTestToken(userID, otherClientID)
			require.NoError(t, store.CreateAccessToken(tok))
		}

		count, err := store.RevokeAllActiveTokensByClientID(clientID)
		require.NoError(t, err)
		assert.Equal(t, int64(3), count, "should revoke only the 3 active tokens")

		// Verify target client's tokens: active ones are now revoked
		tokens, err := store.GetTokensByCategoryAndStatus(
			userID, models.TokenCategoryAccess, models.TokenStatusActive,
		)
		require.NoError(t, err)

		for _, tok := range tokens {
			assert.NotEqual(t, clientID, tok.ClientID,
				"no active tokens should remain for the target client")
		}

		// Other client's tokens should be unaffected
		otherTokens, err := store.GetTokensByCategoryAndStatus(
			userID, models.TokenCategoryAccess, models.TokenStatusActive,
		)
		require.NoError(t, err)
		activeOtherCount := 0
		for _, tok := range otherTokens {
			if tok.ClientID == otherClientID {
				activeOtherCount++
			}
		}
		assert.Equal(t, 2, activeOtherCount, "other client's active tokens should be untouched")
	})

	t.Run("NoActiveTokens", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		clientID := uuid.New().String()
		userID := uuid.New().String()

		// Only revoked tokens exist
		revoked := createTestToken(userID, clientID)
		revoked.Status = models.TokenStatusRevoked
		require.NoError(t, store.CreateAccessToken(revoked))

		count, err := store.RevokeAllActiveTokensByClientID(clientID)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})

	t.Run("NoTokensAtAll", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		count, err := store.RevokeAllActiveTokensByClientID(uuid.New().String())
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}
