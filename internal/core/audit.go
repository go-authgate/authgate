package core

import (
	"context"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store/types"
)

// AuditLogEntry represents the data needed to create an audit log entry.
type AuditLogEntry struct {
	EventType     models.EventType
	Severity      models.EventSeverity
	ActorUserID   string
	ActorUsername string
	ActorIP       string
	ResourceType  models.ResourceType
	ResourceID    string
	ResourceName  string
	Action        string
	Details       models.AuditDetails
	Success       bool
	ErrorMessage  string
	UserAgent     string
	RequestPath   string
	RequestMethod string
}

// AuditLogger defines the contract for audit logging operations.
// Implementations must be safe for concurrent use by multiple goroutines.
// Implementations include the real AuditService (buffered, database-backed)
// and NoopAuditService (silent no-op for when auditing is disabled).
type AuditLogger interface {
	Log(ctx context.Context, entry AuditLogEntry)
	LogSync(ctx context.Context, entry AuditLogEntry) error
	GetAuditLogs(
		params types.PaginationParams,
		filters types.AuditLogFilters,
	) ([]models.AuditLog, types.PaginationResult, error)
	CleanupOldLogs(retention time.Duration) (int64, error)
	GetAuditLogStats(startTime, endTime time.Time) (types.AuditLogStats, error)
	Shutdown(ctx context.Context) error
}
