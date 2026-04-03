package services

import (
	"context"
	"log"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
)

// DashboardStats holds aggregated metrics for the admin dashboard.
type DashboardStats struct {
	store.DashboardCounts
	RegularUsers   int64
	RecentActivity []models.AuditLog
}

type DashboardService struct {
	store        core.Store
	auditService core.AuditLogger
}

func NewDashboardService(
	s core.Store,
	auditService core.AuditLogger,
) *DashboardService {
	if auditService == nil {
		auditService = NewNoopAuditService()
	}
	return &DashboardService{
		store:        s,
		auditService: auditService,
	}
}

// GetDashboardStats returns aggregated stats in a single raw SQL query for
// counts plus one query for recent audit activity.
func (s *DashboardService) GetDashboardStats(ctx context.Context) *DashboardStats {
	stats := &DashboardStats{}

	counts, err := s.store.GetDashboardCounts()
	if err != nil {
		log.Printf("[Dashboard] GetDashboardCounts error: %v", err)
	} else {
		stats.DashboardCounts = counts
		stats.RegularUsers = counts.TotalUsers - counts.AdminUsers
	}

	params := store.NewPaginationParams(1, 10, "")
	if logs, _, err := s.auditService.GetAuditLogs(
		params, store.AuditLogFilters{},
	); err == nil {
		stats.RecentActivity = logs
	} else {
		log.Printf("[Dashboard] GetAuditLogs error: %v", err)
	}

	return stats
}
