package store

import "github.com/go-authgate/authgate/internal/models"

// OAuth Connection operations (implements core.OAuthConnectionStore)

// CreateOAuthConnection creates a new OAuth connection
func (s *Store) CreateOAuthConnection(conn *models.OAuthConnection) error {
	return s.db.Create(conn).Error
}

// GetOAuthConnection finds an OAuth connection by provider and provider user ID
func (s *Store) GetOAuthConnection(
	provider, providerUserID string,
) (*models.OAuthConnection, error) {
	var conn models.OAuthConnection
	err := s.db.Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		First(&conn).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

// GetOAuthConnectionByUserAndProvider finds an OAuth connection by user ID and provider
func (s *Store) GetOAuthConnectionByUserAndProvider(
	userID, provider string,
) (*models.OAuthConnection, error) {
	var conn models.OAuthConnection
	err := s.db.Where("user_id = ? AND provider = ?", userID, provider).
		First(&conn).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

// GetOAuthConnectionsByUserID returns all OAuth connections for a user
func (s *Store) GetOAuthConnectionsByUserID(userID string) ([]models.OAuthConnection, error) {
	var conns []models.OAuthConnection
	err := s.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&conns).Error
	return conns, err
}

// UpdateOAuthConnection updates an existing OAuth connection
func (s *Store) UpdateOAuthConnection(conn *models.OAuthConnection) error {
	return s.db.Save(conn).Error
}

// DeleteOAuthConnection deletes an OAuth connection by ID
func (s *Store) DeleteOAuthConnection(id string) error {
	return s.db.Delete(&models.OAuthConnection{}, "id = ?", id).Error
}

// DeleteOAuthConnectionsByUserID deletes all OAuth connections for a user.
func (s *Store) DeleteOAuthConnectionsByUserID(userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&models.OAuthConnection{}).Error
}
