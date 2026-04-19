package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// getTestConfig returns a minimal config for testing
func getTestConfig() *config.Config {
	return &config.Config{
		DefaultAdminPassword: "", // Use random password in tests
	}
}

// TestStoreWithSQLite tests store operations with SQLite
func TestStoreWithSQLite(t *testing.T) {
	testBasicOperations(t, "sqlite", nil)
}

// TestStoreWithPostgres tests store operations with PostgreSQL
func TestStoreWithPostgres(t *testing.T) {
	// Skip if running short tests or Docker is not available
	if testing.Short() {
		t.Skip("Skipping PostgreSQL integration test in short mode")
	}

	// Recover from panic if Docker is not available
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("Skipping PostgreSQL test: Docker not available (panic: %v)", r)
		}
	}()

	ctx := context.Background()

	// Start PostgreSQL container
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Skipf("Skipping PostgreSQL test: Docker not available (%v)", err)
		return
	}
	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	testBasicOperations(t, "postgres", pgContainer)
}

// createFreshStore creates a new store instance for test isolation
// For SQLite, each call creates a fresh :memory: database
// For PostgreSQL, each call creates a uniquely-named database in the container
func createFreshStore(t *testing.T, driver string, pgContainer *postgres.PostgresContainer) *Store {
	t.Helper()

	// seedData() writes authgate-credentials.txt to the working directory;
	// chdir into a temp dir so it doesn't pollute the repo checkout.
	t.Chdir(t.TempDir())

	var dsn string
	switch driver {
	case "sqlite":
		// SQLite :memory: creates a fresh database for each connection
		dsn = ":memory:"
	case "postgres":
		// Create a unique database name for this subtest using UUID
		dbName := "test_" + uuid.New().String()[:8] // Use first 8 chars of UUID

		ctx := context.Background()

		// Create the database
		createDBCmd := "CREATE DATABASE " + dbName
		_, _, err := pgContainer.Exec(
			ctx,
			[]string{"psql", "-U", "testuser", "-d", "testdb", "-c", createDBCmd},
		)
		require.NoError(t, err)

		// Build connection string for the new database
		host, err := pgContainer.Host(ctx)
		require.NoError(t, err)
		port, err := pgContainer.MappedPort(ctx, "5432")
		require.NoError(t, err)
		dsn = fmt.Sprintf(
			"host=%s port=%s user=testuser password=testpass dbname=%s sslmode=disable",
			host, port.Port(), dbName,
		)

		// Clean up database after test
		t.Cleanup(func() {
			dropDBCmd := "DROP DATABASE IF EXISTS " + dbName
			_, _, _ = pgContainer.Exec(
				context.Background(),
				[]string{"psql", "-U", "testuser", "-d", "testdb", "-c", dropDBCmd},
			)
		})
	default:
		t.Fatalf("unsupported driver: %s", driver)
	}

	store, err := New(context.Background(), driver, dsn, getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

// testBasicOperations tests basic CRUD operations on the store
// Each subtest creates a fresh store instance for isolation
func testBasicOperations(t *testing.T, driver string, pgContainer *postgres.PostgresContainer) {
	t.Run("CreateAndGetUser", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		user := &models.User{
			ID:           uuid.New().String(),
			Username:     "testuser",
			PasswordHash: "hashedpassword",
			Role:         "user",
		}
		err := store.db.Create(user).Error
		require.NoError(t, err)

		retrieved, err := store.GetUserByUsername("testuser")
		require.NoError(t, err)
		assert.Equal(t, user.ID, retrieved.ID)
		assert.Equal(t, user.Username, retrieved.Username)
	})

	t.Run("CreateAndGetClient", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		client := &models.OAuthApplication{
			ClientID:         uuid.New().String(),
			ClientSecret:     "secret",
			ClientName:       "Test Client",
			Description:      "Test Description",
			UserID:           uuid.New().String(),
			Scopes:           "read write",
			GrantTypes:       "device_code",
			RedirectURIs:     models.StringArray{"http://localhost:3000/callback"},
			EnableDeviceFlow: true,
			Status:           models.ClientStatusActive,
		}
		err := store.CreateClient(client)
		require.NoError(t, err)

		retrieved, err := store.GetClient(client.ClientID)
		require.NoError(t, err)
		assert.Equal(t, client.ClientID, retrieved.ClientID)
		assert.Equal(t, client.ClientName, retrieved.ClientName)
	})

	t.Run("CreateAndGetDeviceCode", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		// Generate test device code with hash
		plaintext := "0123456789abcdef0123456789abcdef01234567"
		salt := "testsalt12345678"
		hash := "testhash"

		deviceCode := &models.DeviceCode{
			DeviceCodeHash: hash,
			DeviceCodeSalt: salt,
			DeviceCodeID:   plaintext[len(plaintext)-8:],
			UserCode:       "ABCD1234",
			ClientID:       uuid.New().String(),
			Scopes:         "read write",
			ExpiresAt:      time.Now().Add(30 * time.Minute),
			Interval:       5,
		}
		err := store.CreateDeviceCode(deviceCode)
		require.NoError(t, err)

		// Verify retrieval by ID
		retrieved, err := store.GetDeviceCodesByID(deviceCode.DeviceCodeID)
		require.NoError(t, err)
		assert.Len(t, retrieved, 1)
		assert.Equal(t, deviceCode.UserCode, retrieved[0].UserCode)
		assert.Equal(t, deviceCode.DeviceCodeHash, retrieved[0].DeviceCodeHash)
	})

	t.Run("CreateAndGetAccessToken", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		rawToken := uuid.New().String()
		token := &models.AccessToken{
			ID:        uuid.New().String(),
			TokenHash: util.SHA256Hex(rawToken),
			UserID:    uuid.New().String(),
			ClientID:  uuid.New().String(),
			Scopes:    "read write",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		err := store.CreateAccessToken(token)
		require.NoError(t, err)

		retrieved, err := store.GetAccessTokenByHash(token.TokenHash)
		require.NoError(t, err)
		assert.Equal(t, token.ID, retrieved.ID)
		assert.Equal(t, token.TokenHash, retrieved.TokenHash)
	})

	t.Run("DeleteExpiredTokens", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		// Create expired token
		expiredToken := &models.AccessToken{
			ID:        uuid.New().String(),
			TokenHash: util.SHA256Hex(uuid.New().String()),
			UserID:    uuid.New().String(),
			ClientID:  uuid.New().String(),
			Scopes:    "read write",
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
		}
		err := store.CreateAccessToken(expiredToken)
		require.NoError(t, err)

		// Delete expired tokens
		err = store.DeleteExpiredTokens()
		require.NoError(t, err)

		// Verify token was deleted
		_, err = store.GetAccessTokenByHash(expiredToken.TokenHash)
		assert.Error(t, err)
	})

	t.Run("DeleteExpiredDeviceCodes", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		// Create expired device code
		plaintext := "0123456789abcdef0123456789abcdef01234567"
		expiredCode := &models.DeviceCode{
			DeviceCodeHash: "expiredhash",
			DeviceCodeSalt: "expiredsalt",
			DeviceCodeID:   plaintext[len(plaintext)-8:],
			UserCode:       "EXPIRED1",
			ClientID:       uuid.New().String(),
			Scopes:         "read write",
			ExpiresAt:      time.Now().Add(-1 * time.Hour), // Already expired
			Interval:       5,
		}
		err := store.CreateDeviceCode(expiredCode)
		require.NoError(t, err)

		// Delete expired device codes
		err = store.DeleteExpiredDeviceCodes()
		require.NoError(t, err)

		// Verify device code was deleted
		retrieved, err := store.GetDeviceCodesByID(expiredCode.DeviceCodeID)
		require.NoError(t, err)
		assert.Empty(t, retrieved, "Expired device code should be deleted")
	})

	t.Run("RevokeTokenFamily", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		familyID := uuid.New().String()
		clientID := uuid.New().String()
		userID := uuid.New().String()

		// Create the root refresh token (the family root, already revoked after first rotation)
		parentToken := &models.AccessToken{
			ID:            familyID,
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryRefresh,
			Status:        models.TokenStatusRevoked,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read write",
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			TokenFamilyID: familyID,
		}
		require.NoError(t, store.CreateAccessToken(parentToken))

		// Create child tokens in the same family (all share TokenFamilyID)
		childActive1 := &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read write",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			ParentTokenID: familyID,
			TokenFamilyID: familyID,
		}
		require.NoError(t, store.CreateAccessToken(childActive1))

		// Grandchild — different ParentTokenID but same TokenFamilyID
		grandchildID := uuid.New().String()
		childActive2 := &models.AccessToken{
			ID:            grandchildID,
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryRefresh,
			Status:        models.TokenStatusActive,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read write",
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			ParentTokenID: childActive1.ID,
			TokenFamilyID: familyID,
		}
		require.NoError(t, store.CreateAccessToken(childActive2))

		// Create an already-revoked child (should not be counted again)
		childRevoked := &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryRefresh,
			Status:        models.TokenStatusRevoked,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read write",
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			TokenFamilyID: familyID,
		}
		require.NoError(t, store.CreateAccessToken(childRevoked))

		// Create an unrelated token (different family)
		unrelatedToken := &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			TokenFamilyID: uuid.New().String(), // different family
		}
		require.NoError(t, store.CreateAccessToken(unrelatedToken))

		// Revoke the token family
		revokedCount, err := store.RevokeTokenFamily(familyID)
		require.NoError(t, err)
		// Should revoke the 2 active children (parent already revoked, childRevoked already revoked)
		assert.Equal(t, int64(2), revokedCount)

		// Verify family tokens are revoked (including grandchild)
		retrieved1, err := store.GetAccessTokenByHash(childActive1.TokenHash)
		require.NoError(t, err)
		assert.Equal(t, models.TokenStatusRevoked, retrieved1.Status)

		retrieved2, err := store.GetAccessTokenByHash(childActive2.TokenHash)
		require.NoError(t, err)
		assert.Equal(t, models.TokenStatusRevoked, retrieved2.Status)

		// Verify unrelated token is still active
		unrelated, err := store.GetAccessTokenByHash(unrelatedToken.TokenHash)
		require.NoError(t, err)
		assert.Equal(t, models.TokenStatusActive, unrelated.Status)
	})

	t.Run("HealthCheck", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		err := store.Health()
		assert.NoError(t, err)
	})

	t.Run("GetAuditLogStats", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		now := time.Now()

		// Create audit logs: 2 successful, 1 failed, mixed types and severities
		logs := []models.AuditLog{
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationSuccess,
				EventTime: now.Add(-time.Hour),
				Severity:  models.SeverityInfo,
				Action:    "login",
				Success:   true,
				CreatedAt: now,
			},
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationFailure,
				EventTime: now.Add(-30 * time.Minute),
				Severity:  models.SeverityWarning,
				Action:    "login_fail",
				Success:   false,
				CreatedAt: now,
			},
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationSuccess,
				EventTime: now.Add(-10 * time.Minute),
				Severity:  models.SeverityInfo,
				Action:    "login",
				Success:   true,
				CreatedAt: now,
			},
		}
		for i := range logs {
			err := store.db.Create(&logs[i]).Error
			require.NoError(t, err)
		}

		stats, err := store.GetAuditLogStats(time.Time{}, time.Time{})
		require.NoError(t, err)

		// Verify total counts
		assert.Equal(t, int64(3), stats.TotalEvents)
		assert.Equal(t, int64(2), stats.SuccessCount)
		assert.Equal(t, int64(1), stats.FailureCount)

		// Verify events by type counts ALL events (not just successful)
		assert.Equal(t, int64(2), stats.EventsByType[models.EventAuthenticationSuccess])
		assert.Equal(t, int64(1), stats.EventsByType[models.EventAuthenticationFailure])

		// Verify events by severity counts ALL events (not just successful)
		assert.Equal(t, int64(2), stats.EventsBySeverity[models.SeverityInfo])
		assert.Equal(t, int64(1), stats.EventsBySeverity[models.SeverityWarning])
	})

	t.Run("TokenStatusLifecycle", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		tok := &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        uuid.New().String(),
			ClientID:      uuid.New().String(),
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		}
		require.NoError(t, store.CreateAccessToken(tok))

		// Active → Disabled
		require.NoError(t, store.UpdateTokenStatus(tok.ID, models.TokenStatusDisabled))
		updated, err := store.GetAccessTokenByID(tok.ID)
		require.NoError(t, err)
		assert.Equal(t, models.TokenStatusDisabled, updated.Status)

		// Disabled → Revoked
		require.NoError(t, store.UpdateTokenStatus(tok.ID, models.TokenStatusRevoked))
		updated, err = store.GetAccessTokenByID(tok.ID)
		require.NoError(t, err)
		assert.Equal(t, models.TokenStatusRevoked, updated.Status)
	})

	t.Run("UpdateTokenLastUsedAt", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		tok := &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryRefresh,
			Status:        models.TokenStatusActive,
			UserID:        uuid.New().String(),
			ClientID:      uuid.New().String(),
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(24 * time.Hour),
		}
		require.NoError(t, store.CreateAccessToken(tok))

		now := time.Now()
		require.NoError(t, store.UpdateTokenLastUsedAt(tok.ID, now))

		updated, err := store.GetAccessTokenByID(tok.ID)
		require.NoError(t, err)
		require.NotNil(t, updated.LastUsedAt)
		assert.WithinDuration(t, now, *updated.LastUsedAt, 2*time.Second)
	})

	t.Run("RevokeTokensByUserID", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		userID := uuid.New().String()

		for range 3 {
			tok := &models.AccessToken{
				ID:            uuid.New().String(),
				TokenHash:     util.SHA256Hex(uuid.New().String()),
				TokenCategory: models.TokenCategoryAccess,
				Status:        models.TokenStatusActive,
				UserID:        userID,
				ClientID:      uuid.New().String(),
				Scopes:        "read",
				ExpiresAt:     time.Now().Add(1 * time.Hour),
			}
			require.NoError(t, store.CreateAccessToken(tok))
		}

		require.NoError(t, store.RevokeTokensByUserID(userID))

		tokens, err := store.GetTokensByUserID(userID)
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("RevokeTokensByClientID", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		clientID := uuid.New().String()
		userID := uuid.New().String()

		for range 2 {
			tok := &models.AccessToken{
				ID:            uuid.New().String(),
				TokenHash:     util.SHA256Hex(uuid.New().String()),
				TokenCategory: models.TokenCategoryAccess,
				Status:        models.TokenStatusActive,
				UserID:        userID,
				ClientID:      clientID,
				Scopes:        "read",
				ExpiresAt:     time.Now().Add(1 * time.Hour),
			}
			require.NoError(t, store.CreateAccessToken(tok))
		}

		require.NoError(t, store.RevokeTokensByClientID(clientID))

		// Tokens should be deleted (hard delete) — verify via the user who owned them
		tokens, err := store.GetTokensByUserID(userID)
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("GetTokensByCategoryAndStatus", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		userID := uuid.New().String()
		clientID := uuid.New().String()

		// Active access token
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(time.Hour),
		}))
		// Active refresh token
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryRefresh,
			Status:        models.TokenStatusActive,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(time.Hour),
		}))
		// Revoked access token
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusRevoked,
			UserID:        userID,
			ClientID:      clientID,
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(time.Hour),
		}))

		tokens, err := store.GetTokensByCategoryAndStatus(
			userID,
			models.TokenCategoryAccess,
			models.TokenStatusActive,
		)
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
	})

	t.Run("GetActiveTokenHashesByAuthorizationID", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		clientID := uuid.New().String()
		authzID := uint(42)

		activeHash1 := util.SHA256Hex(uuid.New().String())
		activeHash2 := util.SHA256Hex(uuid.New().String())
		revokedHash := util.SHA256Hex(uuid.New().String())

		// 2 active tokens linked to authorization
		for _, h := range []string{activeHash1, activeHash2} {
			require.NoError(t, store.CreateAccessToken(&models.AccessToken{
				ID:              uuid.New().String(),
				TokenHash:       h,
				TokenCategory:   models.TokenCategoryAccess,
				Status:          models.TokenStatusActive,
				UserID:          uuid.New().String(),
				ClientID:        clientID,
				Scopes:          "read",
				ExpiresAt:       time.Now().Add(time.Hour),
				AuthorizationID: &authzID,
			}))
		}
		// 1 revoked token (should not be returned)
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:              uuid.New().String(),
			TokenHash:       revokedHash,
			TokenCategory:   models.TokenCategoryAccess,
			Status:          models.TokenStatusRevoked,
			UserID:          uuid.New().String(),
			ClientID:        clientID,
			Scopes:          "read",
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthorizationID: &authzID,
		}))

		hashes, err := store.GetActiveTokenHashesByAuthorizationID(authzID)
		require.NoError(t, err)
		assert.Len(t, hashes, 2)
		assert.Contains(t, hashes, activeHash1)
		assert.Contains(t, hashes, activeHash2)
		assert.NotContains(t, hashes, revokedHash)
	})

	t.Run("GetActiveTokenHashesByClientID", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		clientID := uuid.New().String()

		activeHash := util.SHA256Hex(uuid.New().String())
		revokedHash := util.SHA256Hex(uuid.New().String())

		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     activeHash,
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        uuid.New().String(),
			ClientID:      clientID,
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(time.Hour),
		}))
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     revokedHash,
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusRevoked,
			UserID:        uuid.New().String(),
			ClientID:      clientID,
			Scopes:        "read",
			ExpiresAt:     time.Now().Add(time.Hour),
		}))

		hashes, err := store.GetActiveTokenHashesByClientID(clientID)
		require.NoError(t, err)
		assert.Len(t, hashes, 1)
		assert.Contains(t, hashes, activeHash)
		assert.NotContains(t, hashes, revokedHash)
	})

	t.Run("UserCRUD", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		userID := uuid.New().String()

		user := &models.User{
			ID:           userID,
			Username:     "cruduser",
			PasswordHash: "hash",
			Email:        "crud@test.com",
			Role:         "user",
		}
		require.NoError(t, store.CreateUser(user))

		// GetByID
		got, err := store.GetUserByID(userID)
		require.NoError(t, err)
		assert.Equal(t, "cruduser", got.Username)

		// GetByEmail
		got, err = store.GetUserByEmail("crud@test.com")
		require.NoError(t, err)
		assert.Equal(t, userID, got.ID)

		// Update
		user.FullName = "Updated Name"
		require.NoError(t, store.UpdateUser(user))
		got, err = store.GetUserByID(userID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", got.FullName)

		// Delete
		require.NoError(t, store.DeleteUser(userID))
		_, err = store.GetUserByID(userID)
		assert.Error(t, err)
	})

	t.Run("GetUsersByIDs", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		id1, id2 := uuid.New().String(), uuid.New().String()
		u1 := uuid.New().String()[:8]
		u2 := uuid.New().String()[:8]

		require.NoError(t, store.CreateUser(&models.User{
			ID:           id1,
			Username:     "batch_" + u1,
			Email:        u1 + "@test.com",
			PasswordHash: "h",
			Role:         "user",
		}))
		require.NoError(t, store.CreateUser(&models.User{
			ID:           id2,
			Username:     "batch_" + u2,
			Email:        u2 + "@test.com",
			PasswordHash: "h",
			Role:         "user",
		}))

		userMap, err := store.GetUsersByIDs([]string{id1, id2})
		require.NoError(t, err)
		assert.Len(t, userMap, 2)
		assert.Equal(t, "batch_"+u1, userMap[id1].Username)

		// Empty input
		empty, err := store.GetUsersByIDs(nil)
		require.NoError(t, err)
		assert.Empty(t, empty)
	})

	t.Run("ClientUpdateAndDelete", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		client := &models.OAuthApplication{
			ClientID:   uuid.New().String(),
			ClientName: "Original",
			UserID:     uuid.New().String(),
			Status:     models.ClientStatusActive,
		}
		require.NoError(t, store.CreateClient(client))

		// Update
		client.ClientName = "Updated"
		require.NoError(t, store.UpdateClient(client))
		got, err := store.GetClient(client.ClientID)
		require.NoError(t, err)
		assert.Equal(t, "Updated", got.ClientName)

		// Delete
		require.NoError(t, store.DeleteClient(client.ClientID))
		_, err = store.GetClient(client.ClientID)
		assert.Error(t, err)
	})

	t.Run("ListClientsPaginated", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		// Count seed clients first
		seedClients, _, err := store.ListClientsPaginated(PaginationParams{Page: 1, PageSize: 100})
		require.NoError(t, err)
		seedCount := len(seedClients)

		for range 5 {
			require.NoError(t, store.CreateClient(&models.OAuthApplication{
				ClientID:   uuid.New().String(),
				ClientName: "Client",
				UserID:     uuid.New().String(),
				Status:     models.ClientStatusActive,
			}))
		}

		clients, pagination, err := store.ListClientsPaginated(
			PaginationParams{Page: 1, PageSize: 3},
		)
		require.NoError(t, err)
		assert.Len(t, clients, 3)
		assert.Equal(t, int64(5+seedCount), pagination.Total)
		assert.True(t, pagination.HasNext)
	})

	t.Run("CountClientsByStatus", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		// Count seed active clients first
		seedActive, _ := store.CountClientsByStatus(models.ClientStatusActive)

		require.NoError(t, store.CreateClient(&models.OAuthApplication{
			ClientID: uuid.New().String(), ClientName: "A", UserID: uuid.New().String(),
			Status: models.ClientStatusActive,
		}))
		require.NoError(t, store.CreateClient(&models.OAuthApplication{
			ClientID: uuid.New().String(), ClientName: "P", UserID: uuid.New().String(),
			Status: models.ClientStatusPending,
		}))

		active, err := store.CountClientsByStatus(models.ClientStatusActive)
		require.NoError(t, err)
		assert.Equal(t, seedActive+1, active)

		pending, err := store.CountClientsByStatus(models.ClientStatusPending)
		require.NoError(t, err)
		assert.Equal(t, int64(1), pending)
	})

	t.Run("OAuthConnectionCRUD", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		userID := uuid.New().String()
		connID := uuid.New().String()

		conn := &models.OAuthConnection{
			ID:               connID,
			UserID:           userID,
			Provider:         "github",
			ProviderUserID:   "12345",
			ProviderUsername: "ghuser",
			ProviderEmail:    "gh@test.com",
		}
		require.NoError(t, store.CreateOAuthConnection(conn))

		// Get by provider + provider user ID
		got, err := store.GetOAuthConnection("github", "12345")
		require.NoError(t, err)
		assert.Equal(t, connID, got.ID)

		// Get by user + provider
		got, err = store.GetOAuthConnectionByUserAndProvider(userID, "github")
		require.NoError(t, err)
		assert.Equal(t, "ghuser", got.ProviderUsername)

		// List by user
		conns, err := store.GetOAuthConnectionsByUserID(userID)
		require.NoError(t, err)
		assert.Len(t, conns, 1)

		// Update
		conn.ProviderUsername = "updated"
		require.NoError(t, store.UpdateOAuthConnection(conn))
		got, err = store.GetOAuthConnection("github", "12345")
		require.NoError(t, err)
		assert.Equal(t, "updated", got.ProviderUsername)

		// Delete
		require.NoError(t, store.DeleteOAuthConnection(connID))
		_, err = store.GetOAuthConnection("github", "12345")
		assert.Error(t, err)
	})

	t.Run("AuditLogBatchAndFilters", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		now := time.Now()

		logs := []*models.AuditLog{
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationSuccess,
				EventTime: now,
				Severity:  models.SeverityInfo,
				Action:    "login",
				Success:   true,
				CreatedAt: now,
			},
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationFailure,
				EventTime: now,
				Severity:  models.SeverityWarning,
				Action:    "login_fail",
				Success:   false,
				CreatedAt: now,
			},
		}
		require.NoError(t, store.CreateAuditLogBatch(logs))

		// Paginated query
		result, pagination, err := store.GetAuditLogsPaginated(
			PaginationParams{Page: 1, PageSize: 10},
			AuditLogFilters{},
		)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, int64(2), pagination.Total)

		// Filter by event type
		result, _, err = store.GetAuditLogsPaginated(
			PaginationParams{Page: 1, PageSize: 10},
			AuditLogFilters{EventType: models.EventAuthenticationFailure},
		)
		require.NoError(t, err)
		assert.Len(t, result, 1)

		// Delete old logs
		deleted, err := store.DeleteOldAuditLogs(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, int64(2), deleted)
	})

	t.Run("MetricsCounts", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		userID := uuid.New().String()
		clientID := uuid.New().String()

		// Create active access token
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID: uuid.New().String(), TokenHash: util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryAccess, Status: models.TokenStatusActive,
			UserID: userID, ClientID: clientID, Scopes: "read",
			ExpiresAt: time.Now().Add(time.Hour),
		}))
		// Create active refresh token
		require.NoError(t, store.CreateAccessToken(&models.AccessToken{
			ID: uuid.New().String(), TokenHash: util.SHA256Hex(uuid.New().String()),
			TokenCategory: models.TokenCategoryRefresh, Status: models.TokenStatusActive,
			UserID: userID, ClientID: clientID, Scopes: "read",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}))

		accessCount, err := store.CountActiveTokensByCategory(models.TokenCategoryAccess)
		require.NoError(t, err)
		assert.Equal(t, int64(1), accessCount)

		refreshCount, err := store.CountActiveTokensByCategory(models.TokenCategoryRefresh)
		require.NoError(t, err)
		assert.Equal(t, int64(1), refreshCount)

		// Device codes
		require.NoError(t, store.CreateDeviceCode(&models.DeviceCode{
			DeviceCodeHash: "h1", DeviceCodeSalt: "s1", DeviceCodeID: "id000001",
			UserCode: "CODE0001", ClientID: clientID, Scopes: "read",
			ExpiresAt: time.Now().Add(30 * time.Minute), Interval: 5,
		}))

		total, err := store.CountTotalDeviceCodes()
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)

		pending, err := store.CountPendingDeviceCodes()
		require.NoError(t, err)
		assert.Equal(t, int64(1), pending)
	})

	t.Run("RunInTransaction_Success", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		userID := uuid.New().String()

		err := store.RunInTransaction(func(tx core.Store) error {
			return tx.CreateUser(&models.User{
				ID: userID, Username: "txuser", PasswordHash: "h", Role: "user",
			})
		})
		require.NoError(t, err)

		got, err := store.GetUserByID(userID)
		require.NoError(t, err)
		assert.Equal(t, "txuser", got.Username)
	})

	t.Run("RunInTransaction_Rollback", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)
		userID := uuid.New().String()

		err := store.RunInTransaction(func(tx core.Store) error {
			_ = tx.CreateUser(&models.User{
				ID: userID, Username: "rollbackuser", PasswordHash: "h", Role: "user",
			})
			return errors.New("forced rollback")
		})
		require.Error(t, err)

		_, err = store.GetUserByID(userID)
		assert.Error(t, err) // User should not exist due to rollback
	})
}

// TestDriverFactory tests the driver factory pattern
func TestDriverFactory(t *testing.T) {
	tests := []struct {
		name        string
		driver      string
		dsn         string
		expectError bool
	}{
		{
			name:        "SQLite valid",
			driver:      "sqlite",
			dsn:         ":memory:",
			expectError: false,
		},
		{
			name:        "Unsupported driver",
			driver:      "mysql",
			dsn:         "user:pass@tcp(localhost:3306)/dbname",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialector, err := GetDialector(tt.driver, tt.dsn)
			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, dialector)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, dialector)
			}
		})
	}
}

// TestRegisterDriver tests registering custom drivers
func TestRegisterDriver(t *testing.T) {
	// Register a custom driver
	customDriverCalled := false
	RegisterDriver("custom", func(dsn string) gorm.Dialector {
		customDriverCalled = true
		return nil
	})

	// Get the custom driver
	dialector, err := GetDialector("custom", "test-dsn")
	require.NoError(t, err)
	assert.True(t, customDriverCalled)
	assert.Nil(t, dialector) // Our mock returns nil
}

// TestMarkAuthorizationCodeUsed_AtomicDoubleCall verifies that calling
// MarkAuthorizationCodeUsed twice for the same ID returns ErrAuthCodeAlreadyUsed
// on the second call, simulating what happens in a concurrent exchange race.
func TestMarkAuthorizationCodeUsed_AtomicDoubleCall(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	code := &models.AuthorizationCode{
		UUID:          uuid.New().String(),
		CodeHash:      uuid.New().String(),
		CodePrefix:    "abcd1234",
		ApplicationID: 1,
		ClientID:      uuid.New().String(),
		UserID:        uuid.New().String(),
		RedirectURI:   "https://example.com/cb",
		Scopes:        "read",
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	require.NoError(t, store.CreateAuthorizationCode(code))

	// First call must succeed.
	require.NoError(t, store.MarkAuthorizationCodeUsed(code.ID))

	// Second call must fail with ErrAuthCodeAlreadyUsed (0 rows updated).
	err = store.MarkAuthorizationCodeUsed(code.ID)
	require.ErrorIs(t, err, ErrAuthCodeAlreadyUsed)
}

// TestUpsertUserAuthorization_NewRecord verifies that the first call for a
// (user_id, application_id) pair creates a new active record.
func TestUpsertUserAuthorization_NewRecord(t *testing.T) {
	s, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	auth := &models.UserAuthorization{
		UUID:          uuid.New().String(),
		UserID:        uuid.New().String(),
		ApplicationID: 1,
		ClientID:      uuid.New().String(),
		Scopes:        "read",
	}

	require.NoError(t, s.UpsertUserAuthorization(auth))

	stored, err := s.GetUserAuthorization(auth.UserID, auth.ApplicationID)
	require.NoError(t, err)
	assert.True(t, stored.IsActive)
	assert.Nil(t, stored.RevokedAt)
	assert.Equal(t, "read", stored.Scopes)
	assert.Equal(t, auth.ClientID, stored.ClientID)
	assert.False(t, stored.GrantedAt.IsZero())
}

// TestUpsertUserAuthorization_ConflictUpdatesRecord verifies that a second call
// for the same (user_id, application_id) updates the existing row rather than
// inserting a duplicate.
func TestUpsertUserAuthorization_ConflictUpdatesRecord(t *testing.T) {
	s, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	userID := uuid.New().String()
	clientID := uuid.New().String()
	const appID int64 = 1

	first := &models.UserAuthorization{
		UUID:          uuid.New().String(),
		UserID:        userID,
		ApplicationID: appID,
		ClientID:      clientID,
		Scopes:        "read",
	}
	require.NoError(t, s.UpsertUserAuthorization(first))

	// Second upsert with expanded scopes and a new UUID.
	second := &models.UserAuthorization{
		UUID:          uuid.New().String(),
		UserID:        userID,
		ApplicationID: appID,
		ClientID:      clientID,
		Scopes:        "read write",
	}
	require.NoError(t, s.UpsertUserAuthorization(second))

	stored, err := s.GetUserAuthorization(userID, appID)
	require.NoError(t, err)
	assert.Equal(t, "read write", stored.Scopes)
	assert.True(t, stored.IsActive)

	// Only one record should exist for this (user, app) pair.
	var count int64
	s.db.Model(&models.UserAuthorization{}).
		Where("user_id = ? AND application_id = ?", userID, appID).
		Count(&count)
	assert.Equal(t, int64(1), count)
}

// TestUpsertUserAuthorization_ReactivatesRevoked verifies that upserting after a
// revocation re-activates the record and clears RevokedAt.
func TestUpsertUserAuthorization_ReactivatesRevoked(t *testing.T) {
	s, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	userID := uuid.New().String()
	clientID := uuid.New().String()
	const appID int64 = 1

	// Create and then revoke.
	auth := &models.UserAuthorization{
		UUID:          uuid.New().String(),
		UserID:        userID,
		ApplicationID: appID,
		ClientID:      clientID,
		Scopes:        "read",
	}
	require.NoError(t, s.UpsertUserAuthorization(auth))

	stored, err := s.GetUserAuthorization(userID, appID)
	require.NoError(t, err)
	_, err = s.RevokeUserAuthorization(stored.UUID, userID)
	require.NoError(t, err)

	// After revocation, GetUserAuthorization should return nothing (active=false).
	_, err = s.GetUserAuthorization(userID, appID)
	require.Error(t, err)

	// Re-upsert: should re-activate the record.
	reauth := &models.UserAuthorization{
		UUID:          uuid.New().String(),
		UserID:        userID,
		ApplicationID: appID,
		ClientID:      clientID,
		Scopes:        "read write",
	}
	require.NoError(t, s.UpsertUserAuthorization(reauth))

	reactivated, err := s.GetUserAuthorization(userID, appID)
	require.NoError(t, err)
	assert.True(t, reactivated.IsActive)
	assert.Nil(t, reactivated.RevokedAt)
	assert.Equal(t, "read write", reactivated.Scopes)
}

// TestUpsertUserAuthorization_DifferentUsersSameApp verifies that two distinct
// users can each hold an independent consent record for the same application.
func TestUpsertUserAuthorization_DifferentUsersSameApp(t *testing.T) {
	s, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	clientID := uuid.New().String()
	const appID int64 = 1
	userA := uuid.New().String()
	userB := uuid.New().String()

	for _, uid := range []string{userA, userB} {
		a := &models.UserAuthorization{
			UUID:          uuid.New().String(),
			UserID:        uid,
			ApplicationID: appID,
			ClientID:      clientID,
			Scopes:        "read",
		}
		require.NoError(t, s.UpsertUserAuthorization(a))
	}

	storedA, err := s.GetUserAuthorization(userA, appID)
	require.NoError(t, err)
	assert.Equal(t, userA, storedA.UserID)

	storedB, err := s.GetUserAuthorization(userB, appID)
	require.NoError(t, err)
	assert.Equal(t, userB, storedB.UserID)

	// Two separate rows, not one.
	var count int64
	s.db.Model(&models.UserAuthorization{}).
		Where("application_id = ?", appID).
		Count(&count)
	assert.Equal(t, int64(2), count)
}

// BenchmarkStoreOperations benchmarks basic store operations
func BenchmarkStoreOperations(b *testing.B) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(b, err)

	b.Run("CreateUser", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			user := &models.User{
				ID:           uuid.New().String(),
				Username:     fmt.Sprintf("user%d", i),
				PasswordHash: "hashedpassword",
				Role:         "user",
			}
			_ = store.db.Create(user).Error
		}
	})

	b.Run("GetUserByUsername", func(b *testing.B) {
		// Create a user first
		user := &models.User{
			ID:           uuid.New().String(),
			Username:     "benchuser",
			PasswordHash: "hashedpassword",
			Role:         "user",
		}
		_ = store.db.Create(user).Error

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = store.GetUserByUsername("benchuser")
		}
	})
}

// TestUpsertExternalUser_UsernameConflict_OnCreate tests username conflict detection when creating new users
func TestUpsertExternalUser_UsernameConflict_OnCreate(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	// Create a local user first
	localUser := &models.User{
		ID:           uuid.New().String(),
		Username:     "john",
		PasswordHash: "hashedpassword",
		Role:         "user",
		AuthSource:   "local",
	}
	err = store.db.Create(localUser).Error
	require.NoError(t, err)

	// Try to create external user with same username
	_, err = store.UpsertExternalUser(
		"john",         // same username
		"ext-user-123", // different external ID
		"http_api",     // different auth source
		"john@example.com",
		"John Doe",
	)

	// Should return username conflict error
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUsernameConflict)
}

// TestUpsertExternalUser_UsernameConflict_OnUpdate tests username conflict when updating existing user
func TestUpsertExternalUser_UsernameConflict_OnUpdate(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	// Create first external user
	user1, err := store.UpsertExternalUser(
		"john",
		"ext-user-1",
		"http_api",
		"john@example.com",
		"John Doe",
	)
	require.NoError(t, err)
	require.Equal(t, "john", user1.Username)

	// Create second external user
	user2, err := store.UpsertExternalUser(
		"jane",
		"ext-user-2",
		"http_api",
		"jane@example.com",
		"Jane Smith",
	)
	require.NoError(t, err)
	require.Equal(t, "jane", user2.Username)

	// Try to update user2's username to conflict with user1
	_, err = store.UpsertExternalUser(
		"john",       // trying to change to john
		"ext-user-2", // same external ID as user2
		"http_api",
		"jane@example.com",
		"Jane Smith",
	)

	// Should return username conflict error
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUsernameConflict)

	// Verify user2's username unchanged
	user2Check, err := store.GetUserByExternalID("ext-user-2", "http_api")
	require.NoError(t, err)
	assert.Equal(t, "jane", user2Check.Username)
}

// TestUpsertExternalUser_SameUserKeepsUsername tests that same user can keep their username
func TestUpsertExternalUser_SameUserKeepsUsername(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	// Create external user
	user, err := store.UpsertExternalUser(
		"john",
		"ext-user-123",
		"http_api",
		"john@example.com",
		"John Doe",
	)
	require.NoError(t, err)
	require.Equal(t, "john", user.Username)

	// Update same user with same username (should succeed)
	updatedUser, err := store.UpsertExternalUser(
		"john", // same username
		"ext-user-123",
		"http_api",
		"john.doe@example.com", // updated email
		"John A. Doe",          // updated name
	)
	require.NoError(t, err)
	assert.Equal(t, "john", updatedUser.Username)
	assert.Equal(t, "john.doe@example.com", updatedUser.Email)
	assert.Equal(t, "John A. Doe", updatedUser.FullName)
}

// TestUpsertExternalUser_Success_NewUser tests successful creation of new external user
func TestUpsertExternalUser_Success_NewUser(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	user, err := store.UpsertExternalUser(
		"alice",
		"ext-user-456",
		"http_api",
		"alice@example.com",
		"Alice Wonder",
	)

	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, "ext-user-456", user.ExternalID)
	assert.Equal(t, "http_api", user.AuthSource)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "Alice Wonder", user.FullName)
	assert.Equal(t, "user", user.Role)
	assert.Empty(t, user.PasswordHash)
}

// TestUpsertExternalUser_Success_UpdateExisting tests successful update of existing external user
func TestUpsertExternalUser_Success_UpdateExisting(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	// Create user
	user, err := store.UpsertExternalUser(
		"bob",
		"ext-user-789",
		"http_api",
		"bob@example.com",
		"Bob Builder",
	)
	require.NoError(t, err)
	originalID := user.ID

	// Update user info
	updatedUser, err := store.UpsertExternalUser(
		"bob",
		"ext-user-789", // same external ID
		"http_api",
		"bob.builder@example.com", // updated email
		"Robert Builder",          // updated name
	)

	require.NoError(t, err)
	assert.Equal(t, originalID, updatedUser.ID) // ID unchanged
	assert.Equal(t, "bob", updatedUser.Username)
	assert.Equal(t, "bob.builder@example.com", updatedUser.Email)
	assert.Equal(t, "Robert Builder", updatedUser.FullName)
}

// TestUpsertExternalUser_EmailChange_ClearsEmailVerified verifies that when an
// external auth sync changes the user's email, EmailVerified is reset to false.
// External systems can't prove the new address is verified, so ID tokens must
// not continue asserting email_verified=true after the address changes.
func TestUpsertExternalUser_EmailChange_ClearsEmailVerified(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	user, err := store.UpsertExternalUser(
		"carol",
		"ext-carol",
		"http_api",
		"carol@example.com",
		"Carol",
	)
	require.NoError(t, err)

	// Promote to verified, as if a trusted OAuth provider had confirmed it.
	user.EmailVerified = true
	require.NoError(t, store.UpdateUser(user))

	// External sync returns a new email — verification must be downgraded.
	updated, err := store.UpsertExternalUser(
		"carol",
		"ext-carol",
		"http_api",
		"carol.new@example.com",
		"Carol",
	)
	require.NoError(t, err)
	assert.Equal(t, "carol.new@example.com", updated.Email)
	assert.False(t, updated.EmailVerified,
		"changing the email via external sync must downgrade EmailVerified")
}

// TestUpsertExternalUser_EmailWhitespaceOnly_PreservesEmailVerified verifies
// that incidental whitespace from an external provider does not spuriously
// clear EmailVerified. The trimmed email is what ends up stored.
func TestUpsertExternalUser_EmailWhitespaceOnly_PreservesEmailVerified(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	user, err := store.UpsertExternalUser(
		"erin",
		"ext-erin",
		"http_api",
		"erin@example.com",
		"Erin",
	)
	require.NoError(t, err)

	user.EmailVerified = true
	require.NoError(t, store.UpdateUser(user))

	updated, err := store.UpsertExternalUser(
		"erin",
		"ext-erin",
		"http_api",
		"  erin@example.com  ",
		"Erin",
	)
	require.NoError(t, err)
	assert.Equal(t, "erin@example.com", updated.Email,
		"trimmed email must be stored; trailing whitespace must not leak")
	assert.True(t, updated.EmailVerified,
		"whitespace-only differences must not downgrade EmailVerified")
}

// TestUpsertExternalUser_LegacyUnnormalizedEmail_SelfHeals verifies that a
// pre-existing row with incidental whitespace in its stored email does not
// trigger a spurious EmailVerified downgrade on the next sync, and that the
// stored email is rewritten to the trimmed form.
func TestUpsertExternalUser_LegacyUnnormalizedEmail_SelfHeals(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	legacy := &models.User{
		ID:            uuid.New().String(),
		Username:      "legacy",
		Email:         "  legacy@example.com  ", // legacy whitespace
		PasswordHash:  "",
		Role:          models.UserRoleUser,
		IsActive:      true,
		ExternalID:    "ext-legacy",
		AuthSource:    "http_api",
		EmailVerified: true,
	}
	require.NoError(t, store.CreateUser(legacy))

	updated, err := store.UpsertExternalUser(
		"legacy",
		"ext-legacy",
		"http_api",
		"legacy@example.com",
		"Legacy",
	)
	require.NoError(t, err)
	assert.Equal(t, "legacy@example.com", updated.Email,
		"trimmed email must overwrite a legacy value with whitespace")
	assert.True(t, updated.EmailVerified,
		"self-heal must not downgrade EmailVerified when only whitespace differs")
}

// TestUpsertExternalUser_EmptyEmailOnUpdate_KeepsStoredEmail verifies that
// when an external provider omits the email on a subsequent login, the
// stored email and EmailVerified are preserved instead of blanked.
func TestUpsertExternalUser_EmptyEmailOnUpdate_KeepsStoredEmail(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	user, err := store.UpsertExternalUser(
		"flora",
		"ext-flora",
		"http_api",
		"flora@example.com",
		"Flora",
	)
	require.NoError(t, err)
	user.EmailVerified = true
	require.NoError(t, store.UpdateUser(user))

	updated, err := store.UpsertExternalUser(
		"flora",
		"ext-flora",
		"http_api",
		"",
		"",
	)
	require.NoError(t, err)
	assert.Equal(t, "flora@example.com", updated.Email,
		"stored email must be preserved when upstream omits it")
	assert.Equal(t, "Flora", updated.FullName,
		"stored full name must be preserved when upstream omits it")
	assert.True(t, updated.EmailVerified,
		"EmailVerified must not be cleared when upstream omits the email")
}

// TestUpsertExternalUser_EmptyEmailOnCreate_Rejects verifies that creating a
// new external user without an email is rejected — the UNIQUE NOT NULL email
// column cannot hold blank rows.
func TestUpsertExternalUser_EmptyEmailOnCreate_Rejects(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	_, err = store.UpsertExternalUser(
		"ghost",
		"ext-ghost",
		"http_api",
		"",
		"",
	)
	assert.ErrorIs(t, err, ErrExternalUserMissingIdentity)
}

// TestUpsertExternalUser_EmptyUsername_Rejects verifies that a whitespace-only
// username is rejected before reaching the DB.
func TestUpsertExternalUser_EmptyUsername_Rejects(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	_, err = store.UpsertExternalUser(
		"   ",
		"ext-empty",
		"http_api",
		"foo@example.com",
		"Foo",
	)
	assert.ErrorIs(t, err, ErrExternalUserMissingIdentity)
}

// TestUpsertExternalUser_EmailUnchanged_PreservesEmailVerified verifies that
// EmailVerified is preserved when the external sync keeps the same email.
func TestUpsertExternalUser_EmailUnchanged_PreservesEmailVerified(t *testing.T) {
	store, err := New(context.Background(), "sqlite", ":memory:", getTestConfig())
	require.NoError(t, err)

	user, err := store.UpsertExternalUser(
		"dave",
		"ext-dave",
		"http_api",
		"dave@example.com",
		"Dave",
	)
	require.NoError(t, err)

	user.EmailVerified = true
	require.NoError(t, store.UpdateUser(user))

	updated, err := store.UpsertExternalUser(
		"dave",
		"ext-dave",
		"http_api",
		"dave@example.com",
		"David",
	)
	require.NoError(t, err)
	assert.True(t, updated.EmailVerified,
		"EmailVerified must persist when the email is unchanged")
}

// TestDefaultAdminPassword_WhitespaceHandling tests that whitespace-only passwords are treated as empty
func TestDefaultAdminPassword_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name                 string
		defaultAdminPassword string
		shouldUseConfigured  bool
	}{
		{
			name:                 "valid password",
			defaultAdminPassword: "MyPassword123",
			shouldUseConfigured:  true,
		},
		{
			name:                 "password with leading/trailing spaces",
			defaultAdminPassword: "  MyPassword123  ",
			shouldUseConfigured:  true,
		},
		{
			name:                 "empty string",
			defaultAdminPassword: "",
			shouldUseConfigured:  false,
		},
		{
			name:                 "only spaces",
			defaultAdminPassword: "   ",
			shouldUseConfigured:  false,
		},
		{
			name:                 "only tabs",
			defaultAdminPassword: "\t\t\t",
			shouldUseConfigured:  false,
		},
		{
			name:                 "mixed whitespace",
			defaultAdminPassword: " \t\n\r ",
			shouldUseConfigured:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				DefaultAdminPassword: tt.defaultAdminPassword,
			}

			store, err := New(context.Background(), "sqlite", ":memory:", cfg)
			require.NoError(t, err)
			require.NotNil(t, store)

			// Get the created admin user
			admin, err := store.GetUserByUsername("admin")
			require.NoError(t, err)
			require.NotNil(t, admin)

			// Verify the password works
			if tt.shouldUseConfigured {
				// Should use the trimmed configured password
				err = bcrypt.CompareHashAndPassword(
					[]byte(admin.PasswordHash),
					[]byte(strings.TrimSpace(tt.defaultAdminPassword)),
				)
				assert.NoError(t, err, "configured password should work after trimming")
			} else {
				// Should have generated a random password (we can't verify the exact password,
				// but we can verify it's not an empty password)
				assert.NotEmpty(t, admin.PasswordHash)

				// Verify that whitespace-only password does NOT work
				if tt.defaultAdminPassword != "" {
					err = bcrypt.CompareHashAndPassword(
						[]byte(admin.PasswordHash),
						[]byte(tt.defaultAdminPassword),
					)
					assert.Error(t, err, "whitespace-only password should not work")
				}
			}
		})
	}
}

// TestStoreClose tests the Close method with context timeout support
func TestStoreClose(t *testing.T) {
	t.Run("Close with SQLite", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, "sqlite", ":memory:", getTestConfig())
		require.NoError(t, err)
		require.NotNil(t, store)

		// Close with normal context
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err = store.Close(closeCtx)
		assert.NoError(t, err)
	})

	t.Run("Close with timeout", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, "sqlite", ":memory:", getTestConfig())
		require.NoError(t, err)
		require.NotNil(t, store)

		// Close with very short timeout (should still succeed for SQLite)
		closeCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
		defer cancel()
		err = store.Close(closeCtx)
		// For SQLite in-memory, close is fast so this should not timeout
		// But we accept either success or timeout error
		if err != nil {
			assert.Contains(t, err.Error(), "context")
		}
	})

	t.Run("Close with cancelled context", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, "sqlite", ":memory:", getTestConfig())
		require.NoError(t, err)
		require.NotNil(t, store)

		// Close with pre-cancelled context
		closeCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately
		err = store.Close(closeCtx)
		// Close may either succeed quickly or respect the cancelled context.
		if err != nil {
			assert.Contains(t, err.Error(), "database close timeout")
		}
	})

	t.Run("Close and verify connection closed", func(t *testing.T) {
		ctx := context.Background()
		store, err := New(ctx, "sqlite", ":memory:", getTestConfig())
		require.NoError(t, err)
		require.NotNil(t, store)

		// Health check should work before close
		err = store.Health()
		require.NoError(t, err)

		// Close the connection
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err = store.Close(closeCtx)
		require.NoError(t, err)

		// Health check should fail after close
		err = store.Health()
		require.Error(t, err)
	})
}
