package store

import (
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuditLog(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		log := &models.AuditLog{
			ID:            uuid.New().String(),
			EventType:     models.EventAuthenticationSuccess,
			EventTime:     time.Now(),
			Severity:      models.SeverityInfo,
			ActorUserID:   uuid.New().String(),
			ActorUsername: "testuser",
			ActorIP:       "192.168.1.1",
			ResourceType:  models.ResourceUser,
			ResourceID:    uuid.New().String(),
			ResourceName:  "testuser",
			Action:        "login",
			Details:       models.AuditDetails{"method": "local"},
			Success:       true,
			RequestPath:   "/login",
			RequestMethod: "POST",
			CreatedAt:     time.Now(),
		}

		err := store.CreateAuditLog(log)
		require.NoError(t, err)

		// Verify via paginated query
		params := NewPaginationParams(1, 10, "")
		logs, pagination, err := store.GetAuditLogsPaginated(params, AuditLogFilters{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), pagination.Total)
		require.Len(t, logs, 1)
		assert.Equal(t, log.ID, logs[0].ID)
		assert.Equal(t, models.EventAuthenticationSuccess, logs[0].EventType)
	})
}

func TestCreateAuditLogBatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

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

		err := store.CreateAuditLogBatch(logs)
		require.NoError(t, err)

		params := NewPaginationParams(1, 10, "")
		result, pagination, err := store.GetAuditLogsPaginated(params, AuditLogFilters{})
		require.NoError(t, err)
		assert.Equal(t, int64(2), pagination.Total)
		assert.Len(t, result, 2)
	})

	t.Run("empty_batch", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		err := store.CreateAuditLogBatch([]*models.AuditLog{})
		require.NoError(t, err)
	})
}

func TestGetAuditLogsPaginated(t *testing.T) {
	t.Run("with_filters", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		now := time.Now()
		actorID := uuid.New().String()

		// Create mixed logs
		logs := []*models.AuditLog{
			{
				ID:            uuid.New().String(),
				EventType:     models.EventAuthenticationSuccess,
				EventTime:     now.Add(-2 * time.Hour),
				Severity:      models.SeverityInfo,
				ActorUserID:   actorID,
				ActorUsername: "alice",
				ActorIP:       "10.0.0.1",
				ResourceType:  models.ResourceUser,
				Action:        "login",
				Success:       true,
				CreatedAt:     now,
			},
			{
				ID:            uuid.New().String(),
				EventType:     models.EventAuthenticationFailure,
				EventTime:     now.Add(-1 * time.Hour),
				Severity:      models.SeverityWarning,
				ActorUserID:   uuid.New().String(),
				ActorUsername: "bob",
				ActorIP:       "10.0.0.2",
				ResourceType:  models.ResourceUser,
				Action:        "login_fail",
				Success:       false,
				CreatedAt:     now,
			},
			{
				ID:            uuid.New().String(),
				EventType:     models.EventAuthenticationSuccess,
				EventTime:     now,
				Severity:      models.SeverityInfo,
				ActorUserID:   actorID,
				ActorUsername: "alice",
				ActorIP:       "10.0.0.1",
				ResourceType:  models.ResourceUser,
				Action:        "login",
				Success:       true,
				CreatedAt:     now,
			},
		}
		require.NoError(t, store.CreateAuditLogBatch(logs))

		params := NewPaginationParams(1, 10, "")

		// Filter by event type
		result, pagination, err := store.GetAuditLogsPaginated(params, AuditLogFilters{
			EventType: models.EventAuthenticationSuccess,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(2), pagination.Total)
		assert.Len(t, result, 2)

		// Filter by actor user ID
		result, _, err = store.GetAuditLogsPaginated(params, AuditLogFilters{
			ActorUserID: actorID,
		})
		require.NoError(t, err)
		assert.Len(t, result, 2)

		// Filter by severity
		result, _, err = store.GetAuditLogsPaginated(params, AuditLogFilters{
			Severity: models.SeverityWarning,
		})
		require.NoError(t, err)
		assert.Len(t, result, 1)

		// Filter by success
		successTrue := true
		result, _, err = store.GetAuditLogsPaginated(params, AuditLogFilters{
			Success: &successTrue,
		})
		require.NoError(t, err)
		assert.Len(t, result, 2)

		// Filter by IP
		result, _, err = store.GetAuditLogsPaginated(params, AuditLogFilters{
			ActorIP: "10.0.0.2",
		})
		require.NoError(t, err)
		assert.Len(t, result, 1)

		// Filter by search (matches actor_username)
		result, _, err = store.GetAuditLogsPaginated(params, AuditLogFilters{
			Search: "bob",
		})
		require.NoError(t, err)
		assert.Len(t, result, 1)

		// Filter by time range
		result, _, err = store.GetAuditLogsPaginated(params, AuditLogFilters{
			StartTime: now.Add(-90 * time.Minute),
			EndTime:   now.Add(-30 * time.Minute),
		})
		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
}

func TestDeleteOldAuditLogs(t *testing.T) {
	t.Run("deletes_correct_records", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		now := time.Now()

		// Old log (created 2 days ago)
		oldLog := &models.AuditLog{
			ID:        uuid.New().String(),
			EventType: models.EventAuthenticationSuccess,
			EventTime: now.Add(-48 * time.Hour),
			Severity:  models.SeverityInfo,
			Action:    "old_login",
			Success:   true,
			CreatedAt: now.Add(-48 * time.Hour),
		}
		require.NoError(t, store.CreateAuditLog(oldLog))

		// Recent log (created now)
		recentLog := &models.AuditLog{
			ID:        uuid.New().String(),
			EventType: models.EventAuthenticationSuccess,
			EventTime: now,
			Severity:  models.SeverityInfo,
			Action:    "recent_login",
			Success:   true,
			CreatedAt: now,
		}
		require.NoError(t, store.CreateAuditLog(recentLog))

		// Delete logs older than 24 hours
		deleted, err := store.DeleteOldAuditLogs(now.Add(-24 * time.Hour))
		require.NoError(t, err)
		assert.Equal(t, int64(1), deleted)

		// Verify only recent log remains
		params := NewPaginationParams(1, 10, "")
		logs, pagination, err := store.GetAuditLogsPaginated(params, AuditLogFilters{})
		require.NoError(t, err)
		assert.Equal(t, int64(1), pagination.Total)
		require.Len(t, logs, 1)
		assert.Equal(t, recentLog.ID, logs[0].ID)
	})
}

func TestGetAuditLogStats(t *testing.T) {
	t.Run("returns_correct_stats", func(t *testing.T) {
		store := createFreshStore(t, "sqlite", nil)

		now := time.Now()
		logs := []*models.AuditLog{
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationSuccess,
				EventTime: now.Add(-2 * time.Hour),
				Severity:  models.SeverityInfo,
				Action:    "login",
				Success:   true,
				CreatedAt: now,
			},
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationFailure,
				EventTime: now.Add(-1 * time.Hour),
				Severity:  models.SeverityWarning,
				Action:    "login_fail",
				Success:   false,
				CreatedAt: now,
			},
			{
				ID:        uuid.New().String(),
				EventType: models.EventAuthenticationSuccess,
				EventTime: now.Add(-30 * time.Minute),
				Severity:  models.SeverityInfo,
				Action:    "login",
				Success:   true,
				CreatedAt: now,
			},
		}
		require.NoError(t, store.CreateAuditLogBatch(logs))

		// Full range stats (zero times = no filter)
		stats, err := store.GetAuditLogStats(time.Time{}, time.Time{})
		require.NoError(t, err)

		assert.Equal(t, int64(3), stats.TotalEvents)
		assert.Equal(t, int64(2), stats.SuccessCount)
		assert.Equal(t, int64(1), stats.FailureCount)
		assert.Equal(t, int64(2), stats.EventsByType[models.EventAuthenticationSuccess])
		assert.Equal(t, int64(1), stats.EventsByType[models.EventAuthenticationFailure])
		assert.Equal(t, int64(2), stats.EventsBySeverity[models.SeverityInfo])
		assert.Equal(t, int64(1), stats.EventsBySeverity[models.SeverityWarning])

		// Stats with time range filter (only last 90 minutes)
		stats, err = store.GetAuditLogStats(now.Add(-90*time.Minute), now)
		require.NoError(t, err)
		assert.Equal(t, int64(2), stats.TotalEvents)
		assert.Equal(t, int64(1), stats.SuccessCount)
		assert.Equal(t, int64(1), stats.FailureCount)
	})
}
