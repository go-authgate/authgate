package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"
)

// Cleanup and Metrics operations (implements core.CleanupStore + core.MetricsStore)

func (s *Store) DeleteExpiredTokens() error {
	return s.db.Where("expires_at < ?", time.Now()).Delete(&models.AccessToken{}).Error
}

func (s *Store) DeleteExpiredDeviceCodes() error {
	return s.db.Where("expires_at < ?", time.Now()).Delete(&models.DeviceCode{}).Error
}

// GetDashboardCounts returns all dashboard metrics in a single raw SQL query
// using scalar subselects. Works on both SQLite and PostgreSQL.
func (s *Store) GetDashboardCounts() (DashboardCounts, error) {
	var dc DashboardCounts
	now := time.Now()
	err := s.db.Raw(`
		SELECT
			(SELECT COUNT(*) FROM users) AS total_users,
			(SELECT COUNT(*) FROM users WHERE role = ?) AS admin_users,
			(SELECT COUNT(*) FROM oauth_applications) AS total_clients,
			(SELECT COUNT(*) FROM oauth_applications WHERE status = ?) AS active_clients,
			(SELECT COUNT(*) FROM oauth_applications WHERE status = ?) AS pending_clients,
			(SELECT COUNT(*) FROM access_tokens WHERE status = ? AND expires_at > ? AND token_category = ?) AS active_access_tokens,
			(SELECT COUNT(*) FROM access_tokens WHERE status = ? AND expires_at > ? AND token_category = ?) AS active_refresh_tokens
	`,
		models.UserRoleAdmin,
		models.ClientStatusActive,
		models.ClientStatusPending,
		models.TokenStatusActive, now, models.TokenCategoryAccess,
		models.TokenStatusActive, now, models.TokenCategoryRefresh,
	).Scan(&dc).Error
	return dc, err
}

// CountActiveTokensByCategory counts active, non-expired tokens by category
func (s *Store) CountActiveTokensByCategory(category string) (int64, error) {
	var count int64
	err := s.db.Model(&models.AccessToken{}).
		Where("token_category = ? AND status = ? AND expires_at > ?",
			category, models.TokenStatusActive, time.Now()).
		Count(&count).
		Error
	return count, err
}

// CountTotalDeviceCodes counts all non-expired device codes
func (s *Store) CountTotalDeviceCodes() (int64, error) {
	var count int64
	err := s.db.Model(&models.DeviceCode{}).
		Where("expires_at > ?", time.Now()).
		Count(&count).
		Error
	return count, err
}

// CountPendingDeviceCodes counts pending (not yet authorized) device codes
func (s *Store) CountPendingDeviceCodes() (int64, error) {
	var count int64
	err := s.db.Model(&models.DeviceCode{}).
		Where("expires_at > ? AND authorized = ?", time.Now(), false).
		Count(&count).
		Error
	return count, err
}
