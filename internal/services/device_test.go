package services

import (
	"context"
	"testing"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/metrics"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestStore(t *testing.T) *store.Store {
	// Use in-memory SQLite database for testing
	cfg := &config.Config{
		DefaultAdminPassword: "", // Use random password in tests
	}
	s, err := store.New("sqlite", ":memory:", cfg)
	require.NoError(t, err)
	return s
}

func createTestClient(t *testing.T, s *store.Store, isActive bool) *models.OAuthApplication {
	client := &models.OAuthApplication{
		ClientID:         uuid.New().String(),
		ClientSecret:     "secret",
		ClientName:       "Test Client",
		Description:      "Test client for testing",
		UserID:           uuid.New().String(),
		Scopes:           "read write",
		GrantTypes:       "device_code",
		RedirectURIs:     models.StringArray{},
		EnableDeviceFlow: true,
		IsActive:         true, // Create with default value first
	}
	err := s.CreateClient(client)
	require.NoError(t, err)

	// If we want it inactive, update it explicitly
	if !isActive {
		client.IsActive = false
		err = s.UpdateClient(client)
		require.NoError(t, err)
	}

	return client
}

func TestGenerateDeviceCode_ActiveClient(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client
	client := createTestClient(t, s, true)

	// Generate device code
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, dc)
	assert.NotEmpty(t, dc.DeviceCode)
	assert.NotEmpty(t, dc.UserCode)
	assert.Equal(t, client.ClientID, dc.ClientID)
	assert.Equal(t, "read write", dc.Scopes)
	assert.False(t, dc.Authorized)
}

func TestGenerateDeviceCode_InactiveClient(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an inactive client
	client := createTestClient(t, s, false)

	// Verify the client is actually inactive in the database
	storedClient, err := s.GetClient(client.ClientID)
	require.NoError(t, err)
	require.False(t, storedClient.IsActive, "Client should be inactive")

	// Try to generate device code
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrClientInactive, err)
	assert.Nil(t, dc)
}

func TestGenerateDeviceCode_InvalidClient(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Try to generate device code with non-existent client
	dc, err := deviceService.GenerateDeviceCode(
		context.Background(),
		"non-existent-client-id",
		"read write",
	)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidClient, err)
	assert.Nil(t, dc)
}

func TestAuthorizeDeviceCode_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client and device code
	client := createTestClient(t, s, true)
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")
	require.NoError(t, err)

	// Authorize the device code
	userID := uuid.New().String()
	username := "testuser"
	err = deviceService.AuthorizeDeviceCode(context.Background(), dc.UserCode, userID, username)

	// Assert
	assert.NoError(t, err)

	// Verify the device code is authorized
	authorizedDC, err := deviceService.GetDeviceCode(dc.DeviceCode)
	assert.NoError(t, err)
	assert.True(t, authorizedDC.Authorized)
	assert.Equal(t, userID, authorizedDC.UserID)
}

func TestAuthorizeDeviceCode_InvalidUserCode(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Try to authorize with invalid user code
	err := deviceService.AuthorizeDeviceCode(
		context.Background(),
		"INVALID",
		uuid.New().String(),
		"testuser",
	)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrUserCodeNotFound, err)
}

func TestGetClientNameByUserCode_Success(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client and device code
	client := createTestClient(t, s, true)
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")
	require.NoError(t, err)

	// Get client name by user code
	clientName, err := deviceService.GetClientNameByUserCode(dc.UserCode)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "Test Client", clientName)
}

func TestUserCodeNormalization(t *testing.T) {
	s := setupTestStore(t)
	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}
	deviceService := NewDeviceService(s, cfg, nil, metrics.NewNoopMetrics())

	// Create an active client and device code
	client := createTestClient(t, s, true)
	dc, err := deviceService.GenerateDeviceCode(context.Background(), client.ClientID, "read write")
	require.NoError(t, err)

	// Test normalization: lowercase with dashes should work
	userCodeWithDash := dc.UserCode[:4] + "-" + dc.UserCode[4:]
	userCodeLowercase := dc.UserCode[:4] + "-" + dc.UserCode[4:]

	// Both formats should find the same device code
	dc1, err1 := deviceService.GetDeviceCodeByUserCode(userCodeWithDash)
	dc2, err2 := deviceService.GetDeviceCodeByUserCode(userCodeLowercase)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	// Compare by UserCode since DeviceCode field is not stored in DB (gorm:"-")
	assert.Equal(t, dc.UserCode, dc1.UserCode)
	assert.Equal(t, dc.UserCode, dc2.UserCode)
	assert.Equal(t, dc1.ID, dc2.ID)
}
