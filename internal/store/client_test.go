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

// createTestClientWithOpts is a helper that inserts an OAuthApplication with
// customizable fields and returns the persisted record.
func createTestClientWithOpts(
	t *testing.T,
	s *Store,
	overrides *models.OAuthApplication,
) *models.OAuthApplication {
	t.Helper()
	c := &models.OAuthApplication{
		ClientID:         uuid.New().String(),
		ClientSecret:     "secret",
		ClientName:       "Test Client",
		UserID:           uuid.New().String(),
		Scopes:           "read write",
		GrantTypes:       "device_code",
		EnableDeviceFlow: true,
		Status:           models.ClientStatusActive,
	}
	if overrides != nil {
		if overrides.ClientID != "" {
			c.ClientID = overrides.ClientID
		}
		if overrides.ClientName != "" {
			c.ClientName = overrides.ClientName
		}
		if overrides.UserID != "" {
			c.UserID = overrides.UserID
		}
		if overrides.Description != "" {
			c.Description = overrides.Description
		}
		if overrides.Status != "" {
			c.Status = overrides.Status
		}
		if overrides.Scopes != "" {
			c.Scopes = overrides.Scopes
		}
	}
	require.NoError(t, s.CreateClient(c))
	return c
}

func TestListClientsByUserID(t *testing.T) {
	t.Run("returns only clients owned by the user", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		ownerID := uuid.New().String()
		otherID := uuid.New().String()

		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{UserID: ownerID, ClientName: "Owner App 1"},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{UserID: ownerID, ClientName: "Owner App 2"},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{UserID: otherID, ClientName: "Other App"},
		)

		clients, pagination, err := store.ListClientsByUserID(
			ownerID,
			PaginationParams{Page: 1, PageSize: 10},
		)
		require.NoError(t, err)
		assert.Len(t, clients, 2)
		assert.Equal(t, int64(2), pagination.Total)
		for _, c := range clients {
			assert.Equal(t, ownerID, c.UserID)
		}
	})

	t.Run("returns empty when user has no clients", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		createTestClientWithOpts(t, store, nil) // belongs to a random user

		clients, pagination, err := store.ListClientsByUserID(
			uuid.New().String(),
			PaginationParams{Page: 1, PageSize: 10},
		)
		require.NoError(t, err)
		assert.Empty(t, clients)
		assert.Equal(t, int64(0), pagination.Total)
	})

	t.Run("search filters by client name", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		ownerID := uuid.New().String()

		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{UserID: ownerID, ClientName: "My Dashboard"},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{UserID: ownerID, ClientName: "CLI Tool"},
		)

		clients, pagination, err := store.ListClientsByUserID(ownerID, PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "Dashboard",
		})
		require.NoError(t, err)
		assert.Len(t, clients, 1)
		assert.Equal(t, int64(1), pagination.Total)
		assert.Equal(t, "My Dashboard", clients[0].ClientName)
	})

	t.Run("search filters by description", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		ownerID := uuid.New().String()

		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{
				UserID:      ownerID,
				ClientName:  "App A",
				Description: "internal monitoring",
			},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{
				UserID:      ownerID,
				ClientName:  "App B",
				Description: "public api",
			},
		)

		clients, _, err := store.ListClientsByUserID(ownerID, PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "monitoring",
		})
		require.NoError(t, err)
		assert.Len(t, clients, 1)
		assert.Equal(t, "App A", clients[0].ClientName)
	})

	t.Run("pagination works correctly", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		ownerID := uuid.New().String()

		for range 5 {
			createTestClientWithOpts(
				t,
				store,
				&models.OAuthApplication{UserID: ownerID, ClientName: "App"},
			)
		}

		// Page 1 of 3 (page size 2)
		clients, pagination, err := store.ListClientsByUserID(
			ownerID,
			PaginationParams{Page: 1, PageSize: 2},
		)
		require.NoError(t, err)
		assert.Len(t, clients, 2)
		assert.Equal(t, int64(5), pagination.Total)
		assert.Equal(t, 3, pagination.TotalPages)
		assert.True(t, pagination.HasNext)
		assert.False(t, pagination.HasPrev)

		// Page 3 of 3
		clients, pagination, err = store.ListClientsByUserID(
			ownerID,
			PaginationParams{Page: 3, PageSize: 2},
		)
		require.NoError(t, err)
		assert.Len(t, clients, 1)
		assert.False(t, pagination.HasNext)
		assert.True(t, pagination.HasPrev)
	})
}

func TestGetClientsByIDs(t *testing.T) {
	t.Run("returns map of matching clients", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		c1 := createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "First"})
		c2 := createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Second"})
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: "Third"},
		) // not requested

		result, err := store.GetClientsByIDs([]string{c1.ClientID, c2.ClientID})
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "First", result[c1.ClientID].ClientName)
		assert.Equal(t, "Second", result[c2.ClientID].ClientName)
	})

	t.Run("returns empty map for empty input", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		result, err := store.GetClientsByIDs([]string{})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("returns empty map for nil input", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		result, err := store.GetClientsByIDs(nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("ignores nonexistent IDs", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		c1 := createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Exists"})
		bogus := uuid.New().String()

		result, err := store.GetClientsByIDs([]string{c1.ClientID, bogus})
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "Exists", result[c1.ClientID].ClientName)
	})
}

func TestGetClientByIntID(t *testing.T) {
	t.Run("returns client by integer primary key", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		c := createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: "IntID Client"},
		)

		got, err := store.GetClientByIntID(c.ID)
		require.NoError(t, err)
		assert.Equal(t, c.ClientID, got.ClientID)
		assert.Equal(t, "IntID Client", got.ClientName)
	})

	t.Run("returns error when not found", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		_, err := store.GetClientByIntID(999999)
		require.Error(t, err)
	})
}

func TestCountActiveTokensByClientID(t *testing.T) {
	t.Run("counts only active tokens for the client", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		clientID := uuid.New().String()
		userID := uuid.New().String()

		// Create two active tokens
		for range 2 {
			require.NoError(t, store.CreateAccessToken(&models.AccessToken{
				ID:            uuid.New().String(),
				TokenHash:     util.SHA256Hex(uuid.New().String()),
				TokenCategory: models.TokenCategoryAccess,
				Status:        models.TokenStatusActive,
				UserID:        userID,
				ClientID:      clientID,
				Scopes:        "read",
				ExpiresAt:     time.Now().Add(1 * time.Hour),
				TokenFamilyID: uuid.New().String(),
			}))
		}

		// Create a revoked token (should not be counted)
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusRevoked,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			TokenFamilyID: uuid.New().String(),
		}))

		// Create an active token for a different client (should not be counted)
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        userID,
			ClientID:      uuid.New().String(),
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			TokenFamilyID: uuid.New().String(),
		}))

		count, err := store.CountActiveTokensByClientID(clientID)
		require.NoError(t, err)
		assert.Equal(t, int64(2), count)
	})

	t.Run("returns zero when no tokens exist", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		count, err := store.CountActiveTokensByClientID(uuid.New().String())
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})

	t.Run("returns zero when all tokens are revoked or disabled", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		clientID := uuid.New().String()
		userID := uuid.New().String()

		for _, status := range []string{models.TokenStatusRevoked, models.TokenStatusDisabled} {
			require.NoError(t, store.CreateAccessToken(&models.AccessToken{
				ID:            uuid.New().String(),
				TokenHash:     util.SHA256Hex(uuid.New().String()),
				TokenCategory: models.TokenCategoryAccess,
				Status:        status,
				UserID:        userID,
				ClientID:      clientID,
				Scopes:        "read",
				ExpiresAt:     time.Now().Add(1 * time.Hour),
				TokenFamilyID: uuid.New().String(),
			}))
		}

		count, err := store.CountActiveTokensByClientID(clientID)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

func TestListClientsPaginated(t *testing.T) {
	t.Run("returns all clients without filters", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		// The store seeds a default client, so account for that
		createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Extra 1"})
		createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Extra 2"})

		clients, pagination, err := store.ListClientsPaginated(
			PaginationParams{Page: 1, PageSize: 50},
		)
		require.NoError(t, err)
		// At least our 2 + the seeded default
		assert.GreaterOrEqual(t, len(clients), 2)
		assert.Equal(t, pagination.Total, int64(len(clients)))
	})

	t.Run("search filters by client name", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Alpha Service"})
		createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Beta Service"})
		createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Gamma Tool"})

		clients, pagination, err := store.ListClientsPaginated(PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "Service",
		})
		require.NoError(t, err)
		assert.Equal(t, int64(2), pagination.Total)
		assert.Len(t, clients, 2)
		for _, c := range clients {
			assert.Contains(t, c.ClientName, "Service")
		}
	})

	t.Run("search filters by client_id", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		target := createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Needle"})
		createTestClientWithOpts(t, store, &models.OAuthApplication{ClientName: "Haystack"})

		// Search by a substring of the client_id
		searchTerm := target.ClientID[:8]
		clients, _, err := store.ListClientsPaginated(PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   searchTerm,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, clients)
		found := false
		for _, c := range clients {
			if c.ClientID == target.ClientID {
				found = true
			}
		}
		assert.True(t, found, "expected to find client by client_id substring")
	})

	t.Run("status filter returns only matching status", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: "Active One", Status: models.ClientStatusActive},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: "Pending One", Status: models.ClientStatusPending},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{
				ClientName: "Inactive One",
				Status:     models.ClientStatusInactive,
			},
		)

		clients, pagination, err := store.ListClientsPaginated(PaginationParams{
			Page:         1,
			PageSize:     50,
			StatusFilter: models.ClientStatusPending,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(1), pagination.Total)
		assert.Len(t, clients, 1)
		assert.Equal(t, models.ClientStatusPending, clients[0].Status)
	})

	t.Run("combined search and status filter", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: "Foo Active", Status: models.ClientStatusActive},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: "Foo Pending", Status: models.ClientStatusPending},
		)
		createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: "Bar Active", Status: models.ClientStatusActive},
		)

		clients, pagination, err := store.ListClientsPaginated(PaginationParams{
			Page:         1,
			PageSize:     10,
			Search:       "Foo",
			StatusFilter: models.ClientStatusActive,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(1), pagination.Total)
		assert.Len(t, clients, 1)
		assert.Equal(t, "Foo Active", clients[0].ClientName)
	})

	t.Run("pagination returns correct pages", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		// Use a unique name prefix so search isolates from seeded data
		prefix := uuid.New().String()[:6]
		for range 7 {
			createTestClientWithOpts(
				t,
				store,
				&models.OAuthApplication{ClientName: prefix + " App"},
			)
		}

		clients, pagination, err := store.ListClientsPaginated(PaginationParams{
			Page:     1,
			PageSize: 3,
			Search:   prefix,
		})
		require.NoError(t, err)
		assert.Len(t, clients, 3)
		assert.Equal(t, int64(7), pagination.Total)
		assert.Equal(t, 3, pagination.TotalPages)
		assert.True(t, pagination.HasNext)
		assert.False(t, pagination.HasPrev)

		// Last page
		clients, pagination, err = store.ListClientsPaginated(PaginationParams{
			Page:     3,
			PageSize: 3,
			Search:   prefix,
		})
		require.NoError(t, err)
		assert.Len(t, clients, 1)
		assert.False(t, pagination.HasNext)
		assert.True(t, pagination.HasPrev)
	})

	t.Run("empty result with no matching search", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		clients, pagination, err := store.ListClientsPaginated(PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   "zzz_nonexistent_" + uuid.New().String(),
		})
		require.NoError(t, err)
		assert.Empty(t, clients)
		assert.Equal(t, int64(0), pagination.Total)
	})

	t.Run("results ordered by created_at DESC", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		prefix := uuid.New().String()[:6]
		c1 := createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: prefix + " Older"},
		)
		// Ensure different timestamps
		time.Sleep(10 * time.Millisecond)
		c2 := createTestClientWithOpts(
			t,
			store,
			&models.OAuthApplication{ClientName: prefix + " Newer"},
		)

		clients, _, err := store.ListClientsPaginated(PaginationParams{
			Page:     1,
			PageSize: 10,
			Search:   prefix,
		})
		require.NoError(t, err)
		require.Len(t, clients, 2)
		// Newest first
		assert.Equal(t, c2.ClientID, clients[0].ClientID)
		assert.Equal(t, c1.ClientID, clients[1].ClientID)
	})
}
