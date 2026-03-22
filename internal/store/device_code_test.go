package store

import (
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDeviceCodeByUserCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		dc := &models.DeviceCode{
			DeviceCodeHash: "hash-" + uuid.New().String(),
			DeviceCodeSalt: "salt-" + uuid.New().String(),
			DeviceCodeID:   "abcd1234",
			UserCode:       "TESTCODE",
			ClientID:       uuid.New().String(),
			Scopes:         "read write",
			ExpiresAt:      time.Now().Add(30 * time.Minute),
			Interval:       5,
		}
		require.NoError(t, store.CreateDeviceCode(dc))

		retrieved, err := store.GetDeviceCodeByUserCode("TESTCODE")
		require.NoError(t, err)
		assert.Equal(t, dc.ID, retrieved.ID)
		assert.Equal(t, dc.UserCode, retrieved.UserCode)
		assert.Equal(t, dc.ClientID, retrieved.ClientID)
		assert.Equal(t, dc.DeviceCodeHash, retrieved.DeviceCodeHash)
	})

	t.Run("not_found", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		_, err := store.GetDeviceCodeByUserCode("NOEXIST1")
		assert.Error(t, err)
	})
}

func TestUpdateDeviceCode(t *testing.T) {
	t.Run("authorize_device_code", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		dc := &models.DeviceCode{
			DeviceCodeHash: "hash-" + uuid.New().String(),
			DeviceCodeSalt: "salt-" + uuid.New().String(),
			DeviceCodeID:   "efgh5678",
			UserCode:       "AUTHCODE",
			ClientID:       uuid.New().String(),
			Scopes:         "read",
			ExpiresAt:      time.Now().Add(30 * time.Minute),
			Interval:       5,
		}
		require.NoError(t, store.CreateDeviceCode(dc))

		// Authorize the device code
		userID := uuid.New().String()
		dc.Authorized = true
		dc.AuthorizedAt = time.Now()
		dc.UserID = userID
		require.NoError(t, store.UpdateDeviceCode(dc))

		// Verify the update persisted
		retrieved, err := store.GetDeviceCodeByUserCode("AUTHCODE")
		require.NoError(t, err)
		assert.True(t, retrieved.Authorized)
		assert.Equal(t, userID, retrieved.UserID)
		assert.False(t, retrieved.AuthorizedAt.IsZero())
	})
}

func TestDeleteDeviceCodeByID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		dc := &models.DeviceCode{
			DeviceCodeHash: "hash-" + uuid.New().String(),
			DeviceCodeSalt: "salt-" + uuid.New().String(),
			DeviceCodeID:   "ijkl9012",
			UserCode:       "DELCODE1",
			ClientID:       uuid.New().String(),
			Scopes:         "read",
			ExpiresAt:      time.Now().Add(30 * time.Minute),
			Interval:       5,
		}
		require.NoError(t, store.CreateDeviceCode(dc))
		require.NotZero(t, dc.ID)

		// Delete by primary key
		require.NoError(t, store.DeleteDeviceCodeByID(dc.ID))

		// Verify it is gone
		_, err := store.GetDeviceCodeByUserCode("DELCODE1")
		assert.Error(t, err)
	})
}
