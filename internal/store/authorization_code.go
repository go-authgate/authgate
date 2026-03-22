package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"
)

// Authorization Code operations (implements core.AuthorizationCodeStore)

// CreateAuthorizationCode persists a new authorization code
func (s *Store) CreateAuthorizationCode(code *models.AuthorizationCode) error {
	return s.db.Create(code).Error
}

// GetAuthorizationCodeByHash retrieves an authorization code by its SHA-256 hash
func (s *Store) GetAuthorizationCodeByHash(hash string) (*models.AuthorizationCode, error) {
	var code models.AuthorizationCode
	if err := s.db.Where("code_hash = ?", hash).First(&code).Error; err != nil {
		return nil, err
	}
	return &code, nil
}

// MarkAuthorizationCodeUsed atomically sets UsedAt only when the code has not
// yet been consumed.  The WHERE clause includes "used_at IS NULL" so that a
// concurrent request that races past the application-level IsUsed() check will
// update 0 rows and receive ErrAuthCodeAlreadyUsed, preventing double issuance.
func (s *Store) MarkAuthorizationCodeUsed(id uint) error {
	now := time.Now()
	result := s.db.Model(&models.AuthorizationCode{}).
		Where("id = ? AND used_at IS NULL", id).
		Update("used_at", &now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrAuthCodeAlreadyUsed
	}
	return nil
}
