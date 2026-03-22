package store

import "github.com/go-authgate/authgate/internal/models"

// OAuth Client operations (implements core.ClientReader + core.ClientWriter)

func (s *Store) GetClient(clientID string) (*models.OAuthApplication, error) {
	var client models.OAuthApplication
	if err := s.db.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

// ListClientsPaginated returns paginated OAuth clients with search and optional status filter support
func (s *Store) ListClientsPaginated(
	params PaginationParams,
) ([]models.OAuthApplication, PaginationResult, error) {
	var clients []models.OAuthApplication
	var total int64

	// Build base query
	query := s.db.Model(&models.OAuthApplication{})

	// Apply search filter if provided
	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		query = query.Where(
			"client_name LIKE ? OR client_id LIKE ? OR description LIKE ?",
			searchPattern, searchPattern, searchPattern,
		)
	}

	// Apply status filter if provided
	if params.StatusFilter != "" {
		query = query.Where("status = ?", params.StatusFilter)
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
		Find(&clients).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	return clients, pagination, nil
}

// ListClientsByUserID returns paginated OAuth clients owned by the given user
func (s *Store) ListClientsByUserID(
	userID string,
	params PaginationParams,
) ([]models.OAuthApplication, PaginationResult, error) {
	var clients []models.OAuthApplication
	var total int64

	query := s.db.Model(&models.OAuthApplication{}).Where("user_id = ?", userID)

	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		query = query.Where(
			"client_name LIKE ? OR client_id LIKE ? OR description LIKE ?",
			searchPattern, searchPattern, searchPattern,
		)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	pagination := CalculatePagination(total, params.Page, params.PageSize)

	if err := query.Order("created_at DESC").
		Limit(params.PageSize).
		Offset(pagination.Offset()).
		Find(&clients).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	return clients, pagination, nil
}

// CountClientsByStatus returns the number of clients with the given status
func (s *Store) CountClientsByStatus(status string) (int64, error) {
	var count int64
	err := s.db.Model(&models.OAuthApplication{}).
		Where("status = ?", status).
		Count(&count).Error
	return count, err
}

func (s *Store) GetClientsByIDs(clientIDs []string) (map[string]*models.OAuthApplication, error) {
	if len(clientIDs) == 0 {
		return make(map[string]*models.OAuthApplication), nil
	}

	var clients []models.OAuthApplication
	if err := s.db.Where("client_id IN ?", clientIDs).Find(&clients).Error; err != nil {
		return nil, err
	}

	// Convert to map for easy lookup
	clientMap := make(map[string]*models.OAuthApplication, len(clients))
	for i := range clients {
		clientMap[clients[i].ClientID] = &clients[i]
	}

	return clientMap, nil
}

func (s *Store) CreateClient(client *models.OAuthApplication) error {
	return s.db.Create(client).Error
}

func (s *Store) UpdateClient(client *models.OAuthApplication) error {
	return s.db.Save(client).Error
}

func (s *Store) DeleteClient(clientID string) error {
	return s.db.Where("client_id = ?", clientID).Delete(&models.OAuthApplication{}).Error
}

// GetClientByIntID retrieves an OAuth application by its integer primary key
func (s *Store) GetClientByIntID(id int64) (*models.OAuthApplication, error) {
	var client models.OAuthApplication
	if err := s.db.Where("id = ?", id).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

// CountActiveTokensByClientID counts active tokens for a specific client
func (s *Store) CountActiveTokensByClientID(clientID string) (int64, error) {
	var count int64
	err := s.db.Model(&models.AccessToken{}).
		Where("client_id = ? AND status = ?", clientID, models.TokenStatusActive).
		Count(&count).Error
	return count, err
}
