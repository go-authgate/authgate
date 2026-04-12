package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"
)

// GetDashboardCounts returns all dashboard metrics in a single raw SQL query
// using scalar subselects. Works on both SQLite and PostgreSQL.
func (s *Store) GetDashboardCounts() (DashboardCounts, error) {
	var dc DashboardCounts
	now := time.Now()
	err := s.db.Raw(`
		SELECT
			(SELECT COUNT(*) FROM users) AS total_users,
			(SELECT COUNT(*) FROM users WHERE role = ?) AS admin_users,
			(SELECT COUNT(*) FROM users WHERE is_active = ?) AS disabled_users,
			(SELECT COUNT(*) FROM oauth_applications) AS total_clients,
			(SELECT COUNT(*) FROM oauth_applications WHERE status = ?) AS active_clients,
			(SELECT COUNT(*) FROM oauth_applications WHERE status = ?) AS pending_clients,
			(SELECT COUNT(*) FROM access_tokens WHERE status = ? AND expires_at > ? AND token_category = ?) AS active_access_tokens,
			(SELECT COUNT(*) FROM access_tokens WHERE status = ? AND expires_at > ? AND token_category = ?) AS active_refresh_tokens
	`,
		models.UserRoleAdmin,
		false,
		models.ClientStatusActive,
		models.ClientStatusPending,
		models.TokenStatusActive, now, models.TokenCategoryAccess,
		models.TokenStatusActive, now, models.TokenCategoryRefresh,
	).Scan(&dc).Error
	return dc, err
}
