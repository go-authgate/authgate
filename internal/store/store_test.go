package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/appleboy/authgate/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/gorm"
)

// TestStoreWithSQLite tests store operations with SQLite
func TestStoreWithSQLite(t *testing.T) {
	store, err := New("sqlite", ":memory:")
	require.NoError(t, err)
	require.NotNil(t, store)

	testBasicOperations(t, store)
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

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// Create store
	store, err := New("postgres", connStr)
	require.NoError(t, err)
	require.NotNil(t, store)

	testBasicOperations(t, store)
}

// testBasicOperations tests basic CRUD operations on the store
func testBasicOperations(t *testing.T, store *Store) {
	t.Run("CreateAndGetUser", func(t *testing.T) {
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
		client := &models.OAuthClient{
			ClientID:     uuid.New().String(),
			ClientSecret: "secret",
			ClientName:   "Test Client",
			Description:  "Test Description",
			Scopes:       "read write",
			GrantTypes:   "device_code",
			IsActive:     true,
		}
		err := store.CreateClient(client)
		require.NoError(t, err)

		retrieved, err := store.GetClient(client.ClientID)
		require.NoError(t, err)
		assert.Equal(t, client.ClientID, retrieved.ClientID)
		assert.Equal(t, client.ClientName, retrieved.ClientName)
	})

	t.Run("CreateAndGetDeviceCode", func(t *testing.T) {
		deviceCode := &models.DeviceCode{
			DeviceCode: uuid.New().String(),
			UserCode:   "ABCD1234",
			ClientID:   uuid.New().String(),
			Scopes:     "read write",
			ExpiresAt:  time.Now().Add(30 * time.Minute),
			Interval:   5,
		}
		err := store.CreateDeviceCode(deviceCode)
		require.NoError(t, err)

		retrieved, err := store.GetDeviceCode(deviceCode.DeviceCode)
		require.NoError(t, err)
		assert.Equal(t, deviceCode.DeviceCode, retrieved.DeviceCode)
		assert.Equal(t, deviceCode.UserCode, retrieved.UserCode)
	})

	t.Run("CreateAndGetAccessToken", func(t *testing.T) {
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
		// Create expired device code
		expiredCode := &models.DeviceCode{
			DeviceCode: uuid.New().String(),
			UserCode:   "EXPIRED1",
			ClientID:   uuid.New().String(),
			Scopes:     "read write",
			ExpiresAt:  time.Now().Add(-1 * time.Hour), // Already expired
			Interval:   5,
		}
		err := store.CreateDeviceCode(expiredCode)
		require.NoError(t, err)

		// Delete expired device codes
		err = store.DeleteExpiredDeviceCodes()
		require.NoError(t, err)

		// Verify device code was deleted
		_, err = store.GetDeviceCode(expiredCode.DeviceCode)
		assert.Error(t, err)
	})

	t.Run("HealthCheck", func(t *testing.T) {
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

// BenchmarkStoreOperations benchmarks basic store operations
func BenchmarkStoreOperations(b *testing.B) {
	store, err := New("sqlite", ":memory:")
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
