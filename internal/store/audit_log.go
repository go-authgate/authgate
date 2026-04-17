package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"gorm.io/gorm"
)

// Audit Log operations (implements core.AuditStore)

// CreateAuditLog creates a single audit log entry
func (s *Store) CreateAuditLog(log *models.AuditLog) error {
	return s.db.Create(log).Error
}

// CreateAuditLogBatch creates multiple audit log entries in a single transaction
func (s *Store) CreateAuditLogBatch(logs []*models.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	return s.db.CreateInBatches(logs, 100).Error
}

// GetAuditLogsPaginated retrieves audit logs with pagination and filtering
func (s *Store) GetAuditLogsPaginated(
	params PaginationParams,
	filters AuditLogFilters,
) ([]models.AuditLog, PaginationResult, error) {
	var logs []models.AuditLog
	var total int64

	// Build base query
	query := s.db.Model(&models.AuditLog{})

	// Apply filters
	if filters.EventType != "" {
		query = query.Where("event_type = ?", filters.EventType)
	}
	if filters.ActorUserID != "" {
		query = query.Where("actor_user_id = ?", filters.ActorUserID)
	}
	if filters.ResourceType != "" {
		query = query.Where("resource_type = ?", filters.ResourceType)
	}
	if filters.ResourceID != "" {
		query = query.Where("resource_id = ?", filters.ResourceID)
	}
	if filters.Severity != "" {
		query = query.Where("severity = ?", filters.Severity)
	}
	if filters.Success != nil {
		query = query.Where("success = ?", *filters.Success)
	}
	if !filters.StartTime.IsZero() {
		query = query.Where("event_time >= ?", filters.StartTime)
	}
	if !filters.EndTime.IsZero() {
		query = query.Where("event_time <= ?", filters.EndTime)
	}
	if filters.ActorIP != "" {
		query = query.Where("actor_ip = ?", filters.ActorIP)
	}
	if filters.Search != "" {
		searchPattern := "%" + filters.Search + "%"
		query = query.Where(
			"action LIKE ? OR resource_name LIKE ? OR actor_username LIKE ?",
			searchPattern, searchPattern, searchPattern,
		)
	}

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	// Calculate pagination
	pagination := CalculatePagination(total, params.Page, params.PageSize)

	// Apply pagination and fetch results
	if err := query.Order("event_time DESC").
		Limit(params.PageSize).
		Offset(pagination.Offset()).
		Find(&logs).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	return logs, pagination, nil
}

// DeleteOldAuditLogs deletes audit logs older than the specified time in
// bounded batches to keep lock duration short on large tables.
func (s *Store) DeleteOldAuditLogs(olderThan time.Time) (int64, error) {
	return s.deleteByIDInBatches(&models.AuditLog{}, "created_at < ?", olderThan)
}

// GetAuditLogStats returns statistics about audit logs in a given time range
func (s *Store) GetAuditLogStats(startTime, endTime time.Time) (AuditLogStats, error) {
	stats := AuditLogStats{
		EventsByType:     make(map[models.EventType]int64),
		EventsBySeverity: make(map[models.EventSeverity]int64),
	}

	// Build base query as a function to avoid GORM query state mutation
	baseQuery := func() *gorm.DB {
		q := s.db.Model(&models.AuditLog{})
		if !startTime.IsZero() {
			q = q.Where("event_time >= ?", startTime)
		}
		if !endTime.IsZero() {
			q = q.Where("event_time <= ?", endTime)
		}
		return q
	}

	// Total events
	if err := baseQuery().Count(&stats.TotalEvents).Error; err != nil {
		return stats, err
	}

	// Success/Failure counts
	if err := baseQuery().Where("success = ?", true).Count(&stats.SuccessCount).Error; err != nil {
		return stats, err
	}
	stats.FailureCount = stats.TotalEvents - stats.SuccessCount

	// Events by type
	var typeResults []struct {
		EventType models.EventType
		Count     int64
	}
	if err := baseQuery().Select("event_type, COUNT(*) as count").
		Group("event_type").
		Find(&typeResults).Error; err != nil {
		return stats, err
	}
	for _, r := range typeResults {
		stats.EventsByType[r.EventType] = r.Count
	}

	// Events by severity
	var severityResults []struct {
		Severity models.EventSeverity
		Count    int64
	}
	if err := baseQuery().Select("severity, COUNT(*) as count").
		Group("severity").
		Find(&severityResults).Error; err != nil {
		return stats, err
	}
	for _, r := range severityResults {
		stats.EventsBySeverity[r.Severity] = r.Count
	}

	return stats, nil
}
