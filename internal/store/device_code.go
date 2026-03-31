package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"
)

// Device Code operations (implements core.DeviceCodeStore)

// CreateDeviceCode creates a new device code
func (s *Store) CreateDeviceCode(dc *models.DeviceCode) error {
	return s.db.Create(dc).Error
}

// GetDeviceCodesByID retrieves all device codes with matching ID suffix
// Used for hash verification during token exchange
func (s *Store) GetDeviceCodesByID(deviceCodeID string) ([]*models.DeviceCode, error) {
	var dcs []*models.DeviceCode
	if err := s.db.Where("device_code_id = ?", deviceCodeID).Find(&dcs).Error; err != nil {
		return nil, err
	}
	return dcs, nil
}

// GetDeviceCodeByUserCode retrieves a device code by user code
func (s *Store) GetDeviceCodeByUserCode(userCode string) (*models.DeviceCode, error) {
	var dc models.DeviceCode
	if err := s.db.Where("user_code = ?", userCode).First(&dc).Error; err != nil {
		return nil, err
	}
	return &dc, nil
}

// UpdateDeviceCode updates a device code
func (s *Store) UpdateDeviceCode(dc *models.DeviceCode) error {
	return s.db.Save(dc).Error
}

// AuthorizeDeviceCode atomically marks a device code as authorized by a user.
// It uses a WHERE clause to ensure only one concurrent request wins; the loser
// receives ErrDeviceCodeAlreadyAuthorized (0 rows updated).
func (s *Store) AuthorizeDeviceCode(id int64, userID string) error {
	now := time.Now()
	result := s.db.Model(&models.DeviceCode{}).
		Where("id = ? AND authorized = ?", id, false).
		Updates(map[string]any{
			"authorized":    true,
			"authorized_at": now,
			"user_id":       userID,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrDeviceCodeAlreadyAuthorized
	}
	return nil
}

// DeleteDeviceCodeByID deletes device code by ID (primary key)
func (s *Store) DeleteDeviceCodeByID(id int64) error {
	return s.db.Delete(&models.DeviceCode{}, id).Error
}
