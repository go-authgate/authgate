package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"
)

// AuditLogFilters contains filter criteria for querying audit logs
type AuditLogFilters struct {
	EventType    models.EventType     `json:"event_type,omitempty"`
	ActorUserID  string               `json:"actor_user_id,omitempty"`
	ResourceType models.ResourceType  `json:"resource_type,omitempty"`
	ResourceID   string               `json:"resource_id,omitempty"`
	Severity     models.EventSeverity `json:"severity,omitempty"`
	Success      *bool                `json:"success,omitempty"`
	StartTime    time.Time            `json:"start_time,omitzero"`
	EndTime      time.Time            `json:"end_time,omitzero"`
	ActorIP      string               `json:"actor_ip,omitempty"`
	Search       string               `json:"search,omitempty"` // Search in action, resource_name, actor_username
}

// AuditLogStats contains statistics about audit logs
type AuditLogStats struct {
	TotalEvents      int64                          `json:"total_events"`
	EventsByType     map[models.EventType]int64     `json:"events_by_type"`
	EventsBySeverity map[models.EventSeverity]int64 `json:"events_by_severity"`
	SuccessCount     int64                          `json:"success_count"`
	FailureCount     int64                          `json:"failure_count"`
}
