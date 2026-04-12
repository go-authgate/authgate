package store

import (
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withSmallCleanupBatch shrinks the cleanup batch loop parameters for the
// duration of a test so we can exercise the multi-batch path with a realistic
// row count. Restores the production defaults on cleanup.
func withSmallCleanupBatch(t *testing.T, size int) {
	t.Helper()
	origSize := cleanupBatchSize
	origPause := cleanupBatchPause
	cleanupBatchSize = size
	cleanupBatchPause = 0
	t.Cleanup(func() {
		cleanupBatchSize = origSize
		cleanupBatchPause = origPause
	})
}

// seedExpiredTokens creates `count` AccessToken rows already past expiry.
func seedExpiredTokens(t *testing.T, s *Store, count int) {
	t.Helper()
	expired := time.Now().Add(-time.Hour)
	tokens := make([]*models.AccessToken, 0, count)
	for range count {
		tokens = append(tokens, &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     uuid.New().String(),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        "user-" + uuid.New().String(),
			ClientID:      "client-x",
			Scopes:        "read",
			ExpiresAt:     expired,
		})
	}
	require.NoError(t, s.db.CreateInBatches(tokens, 100).Error)
}

// seedActiveTokens creates `count` AccessToken rows still valid for a while.
func seedActiveTokens(t *testing.T, s *Store, count int) {
	t.Helper()
	future := time.Now().Add(time.Hour)
	tokens := make([]*models.AccessToken, 0, count)
	for range count {
		tokens = append(tokens, &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     uuid.New().String(),
			TokenCategory: models.TokenCategoryAccess,
			Status:        models.TokenStatusActive,
			UserID:        "user-" + uuid.New().String(),
			ClientID:      "client-x",
			Scopes:        "read",
			ExpiresAt:     future,
		})
	}
	require.NoError(t, s.db.CreateInBatches(tokens, 100).Error)
}

func TestDeleteExpiredTokensBatched(t *testing.T) {
	withSmallCleanupBatch(t, 100) // force the loop to iterate
	s := createFreshStore(t, "sqlite", nil)

	seedExpiredTokens(t, s, 250)
	seedActiveTokens(t, s, 30)

	require.NoError(t, s.DeleteExpiredTokens())

	var remaining int64
	require.NoError(t, s.db.Model(&models.AccessToken{}).Count(&remaining).Error)
	assert.Equal(t, int64(30), remaining, "only unexpired tokens should remain")
}

func TestDeleteExpiredTokensInvalidBatchSize(t *testing.T) {
	// Guard against a misconfigured batch size silently looping forever: GORM
	// treats Limit(0) as "no limit", so the old termination check never fired.
	withSmallCleanupBatch(t, 0)
	s := createFreshStore(t, "sqlite", nil)

	seedExpiredTokens(t, s, 5)

	err := s.DeleteExpiredTokens()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cleanupBatchSize must be positive")

	var remaining int64
	require.NoError(t, s.db.Model(&models.AccessToken{}).Count(&remaining).Error)
	assert.Equal(t, int64(5), remaining, "no rows should be deleted when guard fires")
}

func TestDeleteExpiredTokensNoRows(t *testing.T) {
	withSmallCleanupBatch(t, 100)
	s := createFreshStore(t, "sqlite", nil)

	// Nothing expired; cleanup must still complete without error and leave
	// everything intact.
	seedActiveTokens(t, s, 10)

	require.NoError(t, s.DeleteExpiredTokens())

	var remaining int64
	require.NoError(t, s.db.Model(&models.AccessToken{}).Count(&remaining).Error)
	assert.Equal(t, int64(10), remaining)
}

func TestDeleteExpiredDeviceCodesBatched(t *testing.T) {
	withSmallCleanupBatch(t, 50)
	s := createFreshStore(t, "sqlite", nil)

	expired := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	expiredCodes := make([]*models.DeviceCode, 0, 120)
	for range 120 {
		expiredCodes = append(expiredCodes, &models.DeviceCode{
			DeviceCodeHash: uuid.New().String(),
			DeviceCodeSalt: "salt",
			DeviceCodeID:   uuid.New().String()[:8],
			UserCode:       uuid.New().String()[:8],
			ClientID:       "client-x",
			Scopes:         "read",
			ExpiresAt:      expired,
		})
	}
	require.NoError(t, s.db.CreateInBatches(expiredCodes, 40).Error)

	activeCodes := make([]*models.DeviceCode, 0, 15)
	for range 15 {
		activeCodes = append(activeCodes, &models.DeviceCode{
			DeviceCodeHash: uuid.New().String(),
			DeviceCodeSalt: "salt",
			DeviceCodeID:   uuid.New().String()[:8],
			UserCode:       uuid.New().String()[:8],
			ClientID:       "client-x",
			Scopes:         "read",
			ExpiresAt:      future,
		})
	}
	require.NoError(t, s.db.CreateInBatches(activeCodes, 40).Error)

	require.NoError(t, s.DeleteExpiredDeviceCodes())

	var remaining int64
	require.NoError(t, s.db.Model(&models.DeviceCode{}).Count(&remaining).Error)
	assert.Equal(t, int64(15), remaining)
}

func TestDeleteOldAuditLogsBatched(t *testing.T) {
	withSmallCleanupBatch(t, 50)
	s := createFreshStore(t, "sqlite", nil)

	// 80 old entries and 20 recent entries; retention cutoff is "now minus 1h"
	oldTime := time.Now().Add(-24 * time.Hour)
	recent := time.Now()

	oldLogs := make([]*models.AuditLog, 0, 80)
	for range 80 {
		oldLogs = append(oldLogs, &models.AuditLog{
			ID:        uuid.New().String(),
			EventType: models.EventAuthenticationSuccess,
			EventTime: oldTime,
			Severity:  models.SeverityInfo,
			Action:    "test",
			CreatedAt: oldTime,
		})
	}
	require.NoError(t, s.db.CreateInBatches(oldLogs, 40).Error)

	newLogs := make([]*models.AuditLog, 0, 20)
	for range 20 {
		newLogs = append(newLogs, &models.AuditLog{
			ID:        uuid.New().String(),
			EventType: models.EventAuthenticationSuccess,
			EventTime: recent,
			Severity:  models.SeverityInfo,
			Action:    "test",
			CreatedAt: recent,
		})
	}
	require.NoError(t, s.db.CreateInBatches(newLogs, 40).Error)

	deleted, err := s.DeleteOldAuditLogs(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(80), deleted)

	var remaining int64
	require.NoError(t, s.db.Model(&models.AuditLog{}).Count(&remaining).Error)
	assert.Equal(t, int64(20), remaining)
}
