package store

import (
	"testing"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestUser inserts a User with customizable fields and returns it.
func createTestUser(t *testing.T, s *Store, overrides *models.User) *models.User {
	t.Helper()
	u := &models.User{
		ID:           uuid.New().String(),
		Username:     "user-" + uuid.New().String()[:8],
		Email:        uuid.New().String()[:8] + "@example.com",
		PasswordHash: "hashed",
		Role:         models.UserRoleUser,
		AuthSource:   models.AuthSourceLocal,
	}
	if overrides != nil {
		if overrides.Username != "" {
			u.Username = overrides.Username
		}
		if overrides.Email != "" {
			u.Email = overrides.Email
		}
		if overrides.Role != "" {
			u.Role = overrides.Role
		}
		if overrides.AuthSource != "" {
			u.AuthSource = overrides.AuthSource
		}
		if overrides.FullName != "" {
			u.FullName = overrides.FullName
		}
	}
	require.NoError(t, s.CreateUser(u))
	return u
}

func TestListUsersPaginated(t *testing.T) {
	t.Run("returns all users with pagination", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		prefix := uuid.New().String()[:6]

		for i := range 5 {
			createTestUser(t, store, &models.User{
				Username: prefix + "-user-" + string(rune('a'+i)),
				Email:    prefix + string(rune('a'+i)) + "@test.com",
			})
		}

		users, pagination, err := store.ListUsersPaginated(
			PaginationParams{Page: 1, PageSize: 3, Search: prefix},
		)
		require.NoError(t, err)
		assert.Len(t, users, 3)
		assert.Equal(t, int64(5), pagination.Total)
		assert.True(t, pagination.HasNext)
		assert.False(t, pagination.HasPrev)

		// Verify password hashes are stripped
		for _, u := range users {
			assert.Empty(t, u.PasswordHash)
		}
	})

	t.Run("search by username email and full name", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		needle := uuid.New().String()[:8]

		createTestUser(t, store, &models.User{
			Username: needle + "-match",
			Email:    "other@test.com",
		})
		createTestUser(t, store, &models.User{
			Username: "nomatch",
			Email:    "nomatch@test.com",
		})

		users, _, err := store.ListUsersPaginated(
			PaginationParams{Page: 1, PageSize: 10, Search: needle},
		)
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Contains(t, users[0].Username, needle)
	})

	t.Run("filter by role", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		prefix := uuid.New().String()[:6]

		createTestUser(t, store, &models.User{
			Username: prefix + "-admin",
			Email:    prefix + "admin@test.com",
			Role:     models.UserRoleAdmin,
		})
		createTestUser(t, store, &models.User{
			Username: prefix + "-user",
			Email:    prefix + "user@test.com",
			Role:     models.UserRoleUser,
		})

		// Filter admin
		users, _, err := store.ListUsersPaginated(
			PaginationParams{
				Page:         1,
				PageSize:     10,
				Search:       prefix,
				StatusFilter: models.UserRoleAdmin,
			},
		)
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, models.UserRoleAdmin, users[0].Role)
	})

	t.Run("filter by auth source", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		prefix := uuid.New().String()[:6]

		createTestUser(t, store, &models.User{
			Username:   prefix + "-local",
			Email:      prefix + "local@test.com",
			AuthSource: models.AuthSourceLocal,
		})
		createTestUser(t, store, &models.User{
			Username:   prefix + "-ext",
			Email:      prefix + "ext@test.com",
			AuthSource: models.AuthSourceHTTPAPI,
		})

		// Filter external
		users, _, err := store.ListUsersPaginated(
			PaginationParams{
				Page:           1,
				PageSize:       10,
				Search:         prefix,
				CategoryFilter: models.AuthSourceHTTPAPI,
			},
		)
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, models.AuthSourceHTTPAPI, users[0].AuthSource)
	})

	t.Run("empty result", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		users, pagination, err := store.ListUsersPaginated(
			PaginationParams{Page: 1, PageSize: 10, Search: "nonexistent-xyz"},
		)
		require.NoError(t, err)
		assert.Empty(t, users)
		assert.Equal(t, int64(0), pagination.Total)
	})
}

func TestCountUsersByRole(t *testing.T) {
	t.Run("counts by role", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		// The seeded admin user already exists, so count starts at 1 admin
		createTestUser(t, store, &models.User{
			Role:  models.UserRoleUser,
			Email: uuid.New().String()[:8] + "@test.com",
		})

		adminCount, err := store.CountUsersByRole(models.UserRoleAdmin)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, adminCount, int64(1))

		userCount, err := store.CountUsersByRole(models.UserRoleUser)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, userCount, int64(1))
	})
}

func TestCountActiveTokensByUserID(t *testing.T) {
	t.Run("zero when no tokens", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		u := createTestUser(t, store, nil)

		count, err := store.CountActiveTokensByUserID(u.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

func TestCountOAuthConnectionsByUserID(t *testing.T) {
	t.Run("zero when no connections", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		u := createTestUser(t, store, nil)

		count, err := store.CountOAuthConnectionsByUserID(u.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

func TestCountUserAuthorizationsByUserID(t *testing.T) {
	t.Run("zero when no authorizations", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)
		u := createTestUser(t, store, nil)

		count, err := store.CountUserAuthorizationsByUserID(u.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}
