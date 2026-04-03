package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopAuditService_Log(t *testing.T) {
	svc := NewNoopAuditService()
	// Should not panic
	svc.Log(context.Background(), core.AuditLogEntry{
		EventType: models.EventAuthenticationSuccess,
		Action:    "test",
	})
}

func TestNoopAuditService_LogSync(t *testing.T) {
	svc := NewNoopAuditService()
	err := svc.LogSync(context.Background(), core.AuditLogEntry{
		EventType: models.EventAuthenticationSuccess,
		Action:    "test",
	})
	require.NoError(t, err)
}

func TestNoopAuditService_GetAuditLogs(t *testing.T) {
	svc := NewNoopAuditService()
	logs, pagination, err := svc.GetAuditLogs(
		types.PaginationParams{Page: 1, PageSize: 10},
		types.AuditLogFilters{},
	)
	require.NoError(t, err)
	assert.NotNil(t, logs)
	assert.Empty(t, logs)
	assert.Equal(t, types.CalculatePagination(0, 1, 10), pagination)
}

func TestNoopAuditService_CleanupOldLogs(t *testing.T) {
	svc := NewNoopAuditService()
	deleted, err := svc.CleanupOldLogs(24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

func TestNoopAuditService_GetAuditLogStats(t *testing.T) {
	svc := NewNoopAuditService()
	stats, err := svc.GetAuditLogStats(time.Now().Add(-24*time.Hour), time.Now())
	require.NoError(t, err)
	assert.NotNil(t, stats.EventsByType)
	assert.NotNil(t, stats.EventsBySeverity)
	assert.Empty(t, stats.EventsByType)
	assert.Empty(t, stats.EventsBySeverity)
}

func TestNoopAuditService_Shutdown(t *testing.T) {
	svc := NewNoopAuditService()
	err := svc.Shutdown(context.Background())
	require.NoError(t, err)
}
