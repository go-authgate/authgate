package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"

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
		createDBCmd := fmt.Sprintf("CREATE DATABASE %s", dbName)
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
			dropDBCmd := fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName)
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
			IsActive:         true,
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

		token := &models.AccessToken{
			ID:        uuid.New().String(),
			Token:     uuid.New().String(),
			UserID:    uuid.New().String(),
			ClientID:  uuid.New().String(),
			Scopes:    "read write",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		err := store.CreateAccessToken(token)
		require.NoError(t, err)

		retrieved, err := store.GetAccessToken(token.Token)
		require.NoError(t, err)
		assert.Equal(t, token.ID, retrieved.ID)
		assert.Equal(t, token.Token, retrieved.Token)
	})

	t.Run("DeleteExpiredTokens", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		// Create expired token
		expiredToken := &models.AccessToken{
			ID:        uuid.New().String(),
			Token:     uuid.New().String(),
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
		_, err = store.GetAccessToken(expiredToken.Token)
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
		assert.Len(t, retrieved, 0, "Expired device code should be deleted")
	})

	t.Run("HealthCheck", func(t *testing.T) {
		store := createFreshStore(t, driver, pgContainer)

		err := store.Health()
		assert.NoError(t, err)
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
				assert.Error(t, err)
				assert.Nil(t, dialector)
			} else {
				assert.NoError(t, err)
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
	assert.NoError(t, err)
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
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUsernameConflict)
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
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUsernameConflict)

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
		assert.NoError(t, err)

		// Close the connection
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err = store.Close(closeCtx)
		assert.NoError(t, err)

		// Health check should fail after close
		err = store.Health()
		assert.Error(t, err)
	})
}
