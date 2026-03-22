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
