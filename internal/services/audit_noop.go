package services

import (
	"context"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store/types"
)

// Compile-time interface check.
var _ core.AuditLogger = (*NoopAuditService)(nil)

// NoopAuditService implements AuditLogger with no-op behavior.
// Used when audit logging is disabled.
type NoopAuditService struct{}

// NewNoopAuditService creates a new no-op audit service.
func NewNoopAuditService() *NoopAuditService {
	return &NoopAuditService{}
}

// Log is a no-op.
func (n *NoopAuditService) Log(_ context.Context, _ core.AuditLogEntry) {}

// LogSync is a no-op.
func (n *NoopAuditService) LogSync(_ context.Context, _ core.AuditLogEntry) error {
	return nil
}

// GetAuditLogs returns empty results.
func (n *NoopAuditService) GetAuditLogs(
	_ types.PaginationParams,
	_ types.AuditLogFilters,
) ([]models.AuditLog, types.PaginationResult, error) {
	return []models.AuditLog{}, types.PaginationResult{}, nil
}

// CleanupOldLogs is a no-op.
func (n *NoopAuditService) CleanupOldLogs(_ time.Duration) (int64, error) {
	return 0, nil
}

// GetAuditLogStats returns empty stats.
func (n *NoopAuditService) GetAuditLogStats(_, _ time.Time) (types.AuditLogStats, error) {
	return types.AuditLogStats{
		EventsByType:     map[models.EventType]int64{},
		EventsBySeverity: map[models.EventSeverity]int64{},
	}, nil
}

// Shutdown is a no-op.
func (n *NoopAuditService) Shutdown(_ context.Context) error {
	return nil
}
