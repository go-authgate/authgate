package store

import (
	"errors"
	"fmt"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User operations (implements core.UserReader + core.UserWriter)

func (s *Store) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByID(id string) (*models.User, error) {
	var user models.User
	if err := s.db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByExternalID finds a user by their external ID and auth source
func (s *Store) GetUserByExternalID(externalID, authSource string) (*models.User, error) {
	var user models.User
	if err := s.db.Where("external_id = ? AND auth_source = ?", externalID, authSource).
		First(&user).
		Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// UpsertExternalUser creates or updates a user from external authentication
func (s *Store) UpsertExternalUser(
	username, externalID, authSource, email, fullName string,
) (*models.User, error) {
	var user models.User

	// Try to find existing user by external ID
	err := s.db.Where("external_id = ? AND auth_source = ?", externalID, authSource).
		First(&user).
		Error

	if err == nil {
		// User exists - check if username changed
		if user.Username != username {
			// Username changed, verify new username is available
			var conflictingUser models.User
			conflictErr := s.db.Where("username = ? AND id != ?", username, user.ID).
				First(&conflictingUser).
				Error

			if conflictErr == nil {
				// Username taken by another user
				return nil, ErrUsernameConflict
			}
			if !errors.Is(conflictErr, gorm.ErrRecordNotFound) {
				// Unexpected database error
				return nil, fmt.Errorf("failed to check username: %w", conflictErr)
			}
			// Username available, continue with update
		}

		// Update user fields
		user.Username = username
		user.Email = email
		user.FullName = fullName
		if err := s.db.Save(&user).Error; err != nil {
			return nil, fmt.Errorf("failed to update external user: %w", err)
		}
		return &user, nil
	}

	// Handle query error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to query external user: %w", err)
	}

	// User doesn't exist - check if username is available
	var existingUser models.User
	err = s.db.Where("username = ?", username).First(&existingUser).Error

	if err == nil {
		// Username already taken
		return nil, ErrUsernameConflict
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		// Unexpected database error
		return nil, fmt.Errorf("failed to check username: %w", err)
	}

	// Create new user
	user = models.User{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: "", // No local password for external users
		Role:         models.UserRoleUser,
		ExternalID:   externalID,
		AuthSource:   authSource,
		Email:        email,
		FullName:     fullName,
	}

	if err := s.db.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to create external user: %w", err)
	}

	return &user, nil
}

// GetUsersByIDs batch loads users by IDs using WHERE IN to prevent N+1 queries
func (s *Store) GetUsersByIDs(userIDs []string) (map[string]*models.User, error) {
	if len(userIDs) == 0 {
		return make(map[string]*models.User), nil
	}

	var users []models.User
	if err := s.db.Where("id IN ?", userIDs).Find(&users).Error; err != nil {
		return nil, err
	}

	// Convert to map for O(1) lookup
	userMap := make(map[string]*models.User, len(users))
	for i := range users {
		userMap[users[i].ID] = &users[i]
	}

	return userMap, nil
}

// GetUserByEmail finds a user by email address
func (s *Store) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateUser creates a new user
func (s *Store) CreateUser(user *models.User) error {
	return s.db.Create(user).Error
}

// UpdateUser updates an existing user
func (s *Store) UpdateUser(user *models.User) error {
	return s.db.Save(user).Error
}

// DeleteUser deletes a user by ID
func (s *Store) DeleteUser(id string) error {
	return s.db.Delete(&models.User{}, "id = ?", id).Error
}
