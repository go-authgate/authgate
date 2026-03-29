package store

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"
)

// Access Token operations (implements core.TokenReader + core.TokenWriter)

func (s *Store) CreateAccessToken(token *models.AccessToken) error {
	return s.db.Create(token).Error
}

func (s *Store) GetAccessTokenByHash(hash string) (*models.AccessToken, error) {
	var t models.AccessToken
	if err := s.db.Where("token_hash = ?", hash).First(&t).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) GetAccessTokenByID(tokenID string) (*models.AccessToken, error) {
	var t models.AccessToken
	if err := s.db.Where("id = ?", tokenID).First(&t).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) GetTokensByUserID(userID string) ([]models.AccessToken, error) {
	var tokens []models.AccessToken
	if err := s.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&tokens).Error; err != nil {
		return nil, err
	}
	return tokens, nil
}

// GetTokensByUserIDPaginated returns paginated tokens for a user with search support
func (s *Store) GetTokensByUserIDPaginated(
	userID string,
	params PaginationParams,
) ([]models.AccessToken, PaginationResult, error) {
	var tokens []models.AccessToken
	var total int64

	// Build base query
	query := s.db.Model(&models.AccessToken{}).Where("user_id = ?", userID)

	// Apply search filter if provided (search in scopes or join with clients for client_name)
	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		// Search in scopes or client_id
		// For client_name search, we'll need to join with oauth_applications
		query = query.Where(
			"scopes LIKE ? OR client_id IN (?)",
			searchPattern,
			s.db.Model(&models.OAuthApplication{}).
				Select("client_id").
				Where("client_name LIKE ?", searchPattern),
		)
	}

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	// Calculate pagination
	pagination := CalculatePagination(total, params.Page, params.PageSize)

	// Apply pagination and fetch results
	if err := query.Order("created_at DESC").
		Limit(params.PageSize).
		Offset(pagination.Offset()).
		Find(&tokens).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	return tokens, pagination, nil
}

func (s *Store) RevokeToken(tokenID string) error {
	return s.db.Where("id = ?", tokenID).Delete(&models.AccessToken{}).Error
}

func (s *Store) RevokeTokensByUserID(userID string) error {
	return s.db.Where("user_id = ?", userID).Delete(&models.AccessToken{}).Error
}

func (s *Store) RevokeTokensByClientID(clientID string) error {
	return s.db.Where("client_id = ?", clientID).Delete(&models.AccessToken{}).Error
}

// UpdateTokenStatus updates the status of a token
func (s *Store) UpdateTokenStatus(tokenID, status string) error {
	return s.db.Model(&models.AccessToken{}).
		Where("id = ?", tokenID).
		Update("status", status).Error
}

// UpdateTokenLastUsedAt updates the last_used_at timestamp of a token
func (s *Store) UpdateTokenLastUsedAt(tokenID string, t time.Time) error {
	return s.db.Model(&models.AccessToken{}).
		Where("id = ?", tokenID).
		Update("last_used_at", &t).Error
}

// RevokeTokenFamily revokes all active tokens that share the same TokenFamilyID.
// This is used for refresh token rotation replay detection: when a revoked refresh token
// is reused, all tokens in the family must be invalidated to prevent stolen token abuse.
func (s *Store) RevokeTokenFamily(familyID string) (int64, error) {
	result := s.db.Model(&models.AccessToken{}).
		Where("token_family_id = ? AND status = ?", familyID, models.TokenStatusActive).
		Update("status", models.TokenStatusRevoked)
	return result.RowsAffected, result.Error
}

// GetActiveTokenHashesByFamilyID returns token hashes for all active tokens in a family.
// Used for cache invalidation before bulk revocation.
func (s *Store) GetActiveTokenHashesByFamilyID(familyID string) ([]string, error) {
	var hashes []string
	err := s.db.Model(&models.AccessToken{}).
		Where("token_family_id = ? AND status = ?", familyID, models.TokenStatusActive).
		Pluck("token_hash", &hashes).Error
	return hashes, err
}

// GetActiveTokenHashesByAuthorizationID returns token hashes for all active tokens
// linked to a specific UserAuthorization. Used for cache invalidation before bulk revocation.
func (s *Store) GetActiveTokenHashesByAuthorizationID(authorizationID uint) ([]string, error) {
	var hashes []string
	err := s.db.Model(&models.AccessToken{}).
		Where("authorization_id = ? AND status = ?", authorizationID, models.TokenStatusActive).
		Pluck("token_hash", &hashes).Error
	return hashes, err
}

// GetActiveTokenHashesByClientID returns token hashes for all active tokens
// belonging to a specific client. Used for cache invalidation before bulk revocation.
func (s *Store) GetActiveTokenHashesByClientID(clientID string) ([]string, error) {
	var hashes []string
	err := s.db.Model(&models.AccessToken{}).
		Where("client_id = ? AND status = ?", clientID, models.TokenStatusActive).
		Pluck("token_hash", &hashes).Error
	return hashes, err
}

// GetTokensByCategoryAndStatus returns tokens filtered by category and status
func (s *Store) GetTokensByCategoryAndStatus(
	userID, category, status string,
) ([]models.AccessToken, error) {
	var tokens []models.AccessToken
	err := s.db.Where("user_id = ? AND token_category = ? AND status = ?", userID, category, status).
		Order("created_at DESC").
		Find(&tokens).
		Error
	return tokens, err
}

// RevokeTokensByAuthorizationID revokes all active tokens linked to a specific UserAuthorization
func (s *Store) RevokeTokensByAuthorizationID(authorizationID uint) error {
	return s.db.Model(&models.AccessToken{}).
		Where("authorization_id = ? AND status = ?", authorizationID, models.TokenStatusActive).
		Update("status", models.TokenStatusRevoked).Error
}

// RevokeAllActiveTokensByClientID revokes every active token for a client and returns the count
func (s *Store) RevokeAllActiveTokensByClientID(clientID string) (int64, error) {
	result := s.db.Model(&models.AccessToken{}).
		Where("client_id = ? AND status = ?", clientID, models.TokenStatusActive).
		Update("status", models.TokenStatusRevoked)
	return result.RowsAffected, result.Error
}
