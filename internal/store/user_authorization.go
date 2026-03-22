package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"gorm.io/gorm/clause"
)

// UserAuthorization operations (implements core.UserAuthorizationStore)

// GetUserAuthorization retrieves the active consent record for a (user, application) pair
func (s *Store) GetUserAuthorization(
	userID string,
	applicationID int64,
) (*models.UserAuthorization, error) {
	var auth models.UserAuthorization
	if err := s.db.Where("user_id = ? AND application_id = ? AND is_active = ?", userID, applicationID, true).
		First(&auth).
		Error; err != nil {
		return nil, err
	}
	return &auth, nil
}

// GetUserAuthorizationByUUID retrieves an authorization by its public UUID, scoped to the owner
func (s *Store) GetUserAuthorizationByUUID(
	authUUID, userID string,
) (*models.UserAuthorization, error) {
	var auth models.UserAuthorization
	if err := s.db.Where("uuid = ? AND user_id = ?", authUUID, userID).
		First(&auth).
		Error; err != nil {
		return nil, err
	}
	return &auth, nil
}

// UpsertUserAuthorization creates a new consent record or re-activates and updates an existing one.
// Uses a single atomic INSERT ... ON CONFLICT DO UPDATE to avoid the race condition that arises
// from a non-atomic SELECT-then-INSERT/UPDATE pattern.
func (s *Store) UpsertUserAuthorization(auth *models.UserAuthorization) error {
	now := time.Now()
	auth.GrantedAt = now
	auth.IsActive = true
	auth.RevokedAt = nil
	return s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "user_id"},
			{Name: "application_id"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"uuid", "client_id", "scopes", "granted_at", "revoked_at", "is_active", "updated_at",
		}),
	}).Create(auth).Error
}

// RevokeUserAuthorization marks an authorization as revoked and returns the record
func (s *Store) RevokeUserAuthorization(
	authUUID, userID string,
) (*models.UserAuthorization, error) {
	var auth models.UserAuthorization
	if err := s.db.Where("uuid = ? AND user_id = ?", authUUID, userID).
		First(&auth).
		Error; err != nil {
		return nil, err
	}
	now := time.Now()
	if err := s.db.Model(&auth).Updates(map[string]any{
		"is_active":  false,
		"revoked_at": &now,
	}).Error; err != nil {
		return nil, err
	}
	return &auth, nil
}

// ListUserAuthorizations returns all active authorizations for a user, newest first
func (s *Store) ListUserAuthorizations(userID string) ([]models.UserAuthorization, error) {
	var auths []models.UserAuthorization
	if err := s.db.Where("user_id = ? AND is_active = ?", userID, true).
		Order("granted_at DESC").
		Find(&auths).Error; err != nil {
		return nil, err
	}
	return auths, nil
}

// RevokeAllUserAuthorizationsByClientID invalidates all active consent records for a client
func (s *Store) RevokeAllUserAuthorizationsByClientID(clientID string) error {
	now := time.Now()
	return s.db.Model(&models.UserAuthorization{}).
		Where("client_id = ? AND is_active = ?", clientID, true).
		Updates(map[string]any{
			"is_active":  false,
			"revoked_at": &now,
		}).Error
}

// GetClientAuthorizations returns all active consent records for a client, ordered by grant date
func (s *Store) GetClientAuthorizations(clientID string) ([]models.UserAuthorization, error) {
	var auths []models.UserAuthorization
	if err := s.db.Where("client_id = ? AND is_active = ?", clientID, true).
		Order("granted_at DESC").
		Find(&auths).Error; err != nil {
		return nil, err
	}
	return auths, nil
}
