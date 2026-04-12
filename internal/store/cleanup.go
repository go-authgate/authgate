package store

import (
	"fmt"
	"time"

	"github.com/go-authgate/authgate/internal/models"
)

// Cleanup and Metrics operations (implements core.CleanupStore + core.MetricsStore)

// cleanupBatchSize bounds each DELETE to keep lock duration short on large tables.
// Chosen empirically: 10k rows × a single indexed DELETE completes in well under
// a second even on a busy PostgreSQL, so replicas / WAL apply do not fall behind.
// Declared as var (not const) so tests can shrink it to exercise the batching loop.
var cleanupBatchSize = 10000

// cleanupBatchPause gives WAL / replication / autovacuum breathing room between
// batches. A short sleep is sufficient; we are optimizing for background-job
// friendliness, not throughput. Declared as var so tests can zero it out.
var cleanupBatchPause = 200 * time.Millisecond

// deleteByIDInBatches DELETEs rows of `model` matching whereClause in batches of
// cleanupBatchSize, using the subquery form `id IN (SELECT id … LIMIT N)`.
// PostgreSQL does not support `DELETE … LIMIT` directly, and this form lets the
// inner SELECT use the WHERE-clause index (e.g. expires_at).
//
// The helper assumes `model` has an `id` primary-key column — all current
// cleanup targets (AccessToken, DeviceCode, AuditLog) satisfy this. Do not call
// it with models whose PK column is named differently.
func (s *Store) deleteByIDInBatches(
	model any,
	whereClause string,
	args ...any,
) (int64, error) {
	if cleanupBatchSize <= 0 {
		return 0, fmt.Errorf("cleanupBatchSize must be positive, got %d", cleanupBatchSize)
	}
	var total int64
	for {
		sub := s.db.Model(model).
			Select("id").
			Where(whereClause, args...).
			Limit(cleanupBatchSize)
		res := s.db.Where("id IN (?)", sub).Delete(model)
		if res.Error != nil {
			return total, res.Error
		}
		total += res.RowsAffected
		if res.RowsAffected == 0 || res.RowsAffected < int64(cleanupBatchSize) {
			return total, nil
		}
		time.Sleep(cleanupBatchPause)
	}
}

// DeleteExpiredTokens removes access/refresh tokens past expiry.
func (s *Store) DeleteExpiredTokens() error {
	_, err := s.deleteByIDInBatches(&models.AccessToken{}, "expires_at < ?", time.Now())
	return err
}

// DeleteExpiredDeviceCodes removes device authorization codes past expiry.
func (s *Store) DeleteExpiredDeviceCodes() error {
	_, err := s.deleteByIDInBatches(&models.DeviceCode{}, "expires_at < ?", time.Now())
	return err
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
