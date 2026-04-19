package store

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store/types"

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
	// Normalize inputs so incidental whitespace from upstream providers does
	// not pollute storage or spuriously downgrade EmailVerified on the next
	// login. Matches the trimming performed by the admin create/update paths.
	username = strings.TrimSpace(username)
	externalID = strings.TrimSpace(externalID)
	authSource = strings.TrimSpace(authSource)
	email = strings.TrimSpace(email)
	fullName = strings.TrimSpace(fullName)

	// Username and the (externalID, authSource) lookup key are required on
	// every call. A blank externalID would collapse unrelated external
	// accounts onto whichever row it matched first, so reject early.
	if username == "" || externalID == "" || authSource == "" {
		return nil, ErrExternalUserMissingIdentity
	}

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

		user.Username = username
		// Only overwrite email/fullName when upstream actually provided a
		// value — some external auth responses (e.g. HTTP API) return only
		// username+external_id, and blanking the stored email would break
		// the UNIQUE/NOT NULL constraint and wipe verification state.
		if email != "" {
			// An external system has no way to prove that the new email is
			// verified, so downgrade whenever the stored email changes.
			// Compare trimmed values so a legacy row with incidental
			// whitespace does not look like a real change.
			if strings.TrimSpace(user.Email) != email {
				user.EmailVerified = false
			}
			user.Email = email
		}
		if fullName != "" {
			user.FullName = fullName
		}
		if err := s.db.Save(&user).Error; err != nil {
			return nil, fmt.Errorf("failed to update external user: %w", err)
		}
		return &user, nil
	}

	// Handle query error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to query external user: %w", err)
	}

	// Email is required to create a new external user — it's a UNIQUE NOT NULL
	// column, and blank rows would collide with each other. (The update branch
	// above is intentionally lenient, since older rows already carry a valid
	// email even when upstream omits it on subsequent logins.)
	if email == "" {
		return nil, ErrExternalUserMissingIdentity
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
		IsActive:     true,
		ExternalID:   externalID,
		AuthSource:   authSource,
		Email:        email,
		FullName:     fullName,
	}

	if err := s.db.Create(&user).Error; err != nil {
		// GORM TranslateError maps driver-specific unique constraint violations
		// to gorm.ErrDuplicatedKey. Re-check username to confirm the conflict
		// is on username (not email or another unique field).
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			if existing, lookupErr := s.GetUserByUsername(
				username,
			); lookupErr == nil &&
				existing != nil {
				return nil, ErrUsernameConflict
			}
		}
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

// GetUserByEmail finds a user by email address. The lookup is resilient to
// incidental whitespace on either side: the argument is trimmed, and if no
// indexed exact match is found, a fallback scan on TRIM(email) lets callers
// still locate legacy rows written before email normalization was enforced.
func (s *Store) GetUserByEmail(email string) (*models.User, error) {
	email = strings.TrimSpace(email)

	var user models.User
	err := s.db.Where("email = ?", email).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// Fallback: legacy rows may have incidental whitespace in the stored
	// value. This query bypasses the unique index but is only reached on a
	// primary miss, so the cost stays bounded.
	if err := s.db.Where("TRIM(email) = ?", email).First(&user).Error; err != nil {
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

// ListUsersPaginated returns paginated users with search, role, and auth source filtering.
func (s *Store) ListUsersPaginated(
	params PaginationParams,
) ([]models.User, PaginationResult, error) {
	var users []models.User
	var total int64

	query := s.db.Model(&models.User{})

	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		query = query.Where(
			"username LIKE ? OR email LIKE ? OR full_name LIKE ?",
			searchPattern, searchPattern, searchPattern,
		)
	}

	// StatusFilter is reused as role filter
	if params.StatusFilter != "" {
		query = query.Where("role = ?", params.StatusFilter)
	}

	// CategoryFilter is reused as auth_source filter
	if params.CategoryFilter != "" {
		query = query.Where("auth_source = ?", params.CategoryFilter)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	pagination := CalculatePagination(total, params.Page, params.PageSize)

	if err := query.Order("created_at DESC").
		Limit(params.PageSize).
		Offset(pagination.Offset()).
		Omit("password_hash").
		Find(&users).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	return users, pagination, nil
}

// CountUsersByRole returns the number of active users with the given role.
// Only active users are counted so that disabled admins do not inflate the
// "last admin" guard used by disable/delete operations.
func (s *Store) CountUsersByRole(role string) (int64, error) {
	var count int64
	query := s.db.Model(&models.User{}).Where("is_active = ?", true)
	if role != "" {
		query = query.Where("role = ?", role)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetUserStatsByUserID returns all user stats (active tokens, OAuth connections,
// active authorizations) in a single database query using subqueries.
func (s *Store) GetUserStatsByUserID(userID string) (types.UserStatsCounts, error) {
	var result struct {
		ActiveTokenCount         int64 `gorm:"column:active_token_count"`
		OAuthConnCount           int64 `gorm:"column:oauth_conn_count"`
		ActiveAuthorizationCount int64 `gorm:"column:active_authorization_count"`
	}
	err := s.db.Raw(`
		SELECT
			(SELECT COUNT(*) FROM access_tokens WHERE user_id = ? AND status = ?) AS active_token_count,
			(SELECT COUNT(*) FROM oauth_connections WHERE user_id = ?) AS oauth_conn_count,
			(SELECT COUNT(*) FROM user_authorizations WHERE user_id = ? AND is_active = ?) AS active_authorization_count
	`, userID, models.TokenStatusActive, userID, userID, true).Scan(&result).Error
	if err != nil {
		return types.UserStatsCounts{}, err
	}
	return types.UserStatsCounts{
		ActiveTokenCount:         result.ActiveTokenCount,
		OAuthConnectionCount:     result.OAuthConnCount,
		ActiveAuthorizationCount: result.ActiveAuthorizationCount,
	}, nil
}
