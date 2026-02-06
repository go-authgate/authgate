package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Store struct {
	db *gorm.DB
}

func New(driver, dsn string, cfg *config.Config) (*Store, error) {
	dialector, err := GetDialector(driver, dsn)
	if err != nil {
		return nil, err
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, err
	}

	// Auto migrate
	if err := db.AutoMigrate(
		&models.User{},
		&models.OAuthApplication{},
		&models.DeviceCode{},
		&models.AccessToken{},
		&models.OAuthConnection{},
		&models.AuditLog{},
	); err != nil {
		return nil, err
	}

	// Configure connection pool (after AutoMigrate)
	// Only configure if values are provided (non-zero)
	if cfg.DBMaxOpenConns > 0 || cfg.DBMaxIdleConns > 0 ||
		cfg.DBConnMaxLifetime > 0 || cfg.DBConnMaxIdleTime > 0 {
		sqlDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("failed to get database instance: %w", err)
		}

		// Set connection pool parameters
		if cfg.DBMaxOpenConns > 0 {
			sqlDB.SetMaxOpenConns(cfg.DBMaxOpenConns)
		}
		if cfg.DBMaxIdleConns > 0 {
			sqlDB.SetMaxIdleConns(cfg.DBMaxIdleConns)
		}
		if cfg.DBConnMaxLifetime > 0 {
			sqlDB.SetConnMaxLifetime(cfg.DBConnMaxLifetime)
		}
		if cfg.DBConnMaxIdleTime > 0 {
			sqlDB.SetConnMaxIdleTime(cfg.DBConnMaxIdleTime)
		}

		log.Printf(
			"Database connection pool configured: MaxOpen=%d, MaxIdle=%d, MaxLifetime=%v, MaxIdleTime=%v",
			cfg.DBMaxOpenConns,
			cfg.DBMaxIdleConns,
			cfg.DBConnMaxLifetime,
			cfg.DBConnMaxIdleTime,
		)
	}

	store := &Store{db: db}

	// Seed default data
	if err := store.seedData(cfg); err != nil {
		log.Printf("Warning: failed to seed data: %v", err)
	}

	return store, nil
}

// generateRandomPassword generates a random password of specified length
func generateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Use base64 URL encoding to get a safe, printable password
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func (s *Store) seedData(cfg *config.Config) error {
	// Create default user if not exists
	var userCount int64
	s.db.Model(&models.User{}).Count(&userCount)
	userID := uuid.New().String()
	if userCount == 0 {
		var password string
		var err error

		// Use configured password if set (after trimming whitespace), otherwise generate random password
		configuredPassword := strings.TrimSpace(cfg.DefaultAdminPassword)
		if configuredPassword != "" {
			password = configuredPassword
		} else {
			password, err = generateRandomPassword(16)
			if err != nil {
				return err
			}
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user := &models.User{
			ID:           userID,
			Username:     "admin",
			Email:        "admin@localhost", // Default email for admin
			PasswordHash: string(hash),
			Role:         "admin",
		}
		if err := s.db.Create(user).Error; err != nil {
			return err
		}

		// Log password creation differently based on source
		if configuredPassword != "" {
			log.Printf("Created default user: admin / [configured password] (role: admin)")
		} else {
			log.Printf("Created default user: admin / %s (role: admin)", password)
		}
	}

	// Create default OAuth client if not exists
	var clientCount int64
	s.db.Model(&models.OAuthApplication{}).Count(&clientCount)
	if clientCount == 0 {
		clientID := uuid.New().String()
		clientSecret := uuid.New().String()
		secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		client := &models.OAuthApplication{
			UserID:           userID,
			ClientID:         clientID,
			ClientSecret:     string(secretHash),
			ClientName:       "AuthGate CLI",
			Description:      "Default CLI client for device authorization flow",
			Scopes:           "read write",
			GrantTypes:       "device_code",
			RedirectURIs:     models.StringArray{},
			EnableDeviceFlow: true,
			IsActive:         true,
		}
		if err := s.db.Create(client).Error; err != nil {
			return err
		}
		log.Printf("Created default OAuth client: %s (AuthGate CLI)", clientID)
		log.Printf("Client Secret (save this): %s", clientSecret)
	}

	return nil
}

// User operations
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
	if err := s.db.Where("external_id = ? AND auth_source = ?", externalID, authSource).First(&user).Error; err != nil {
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
		Role:         "user",
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

// OAuth Client operations
func (s *Store) GetClient(clientID string) (*models.OAuthApplication, error) {
	var client models.OAuthApplication
	if err := s.db.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *Store) ListClients() ([]models.OAuthApplication, error) {
	var clients []models.OAuthApplication
	if err := s.db.Order("created_at DESC").Find(&clients).Error; err != nil {
		return nil, err
	}
	return clients, nil
}

// ListClientsPaginated returns paginated OAuth clients with search support
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

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	// Calculate pagination
	pagination := CalculatePagination(total, params.Page, params.PageSize)

	// Apply pagination and fetch results
	offset := (params.Page - 1) * params.PageSize
	if err := query.Order("created_at DESC").
		Limit(params.PageSize).
		Offset(offset).
		Find(&clients).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	return clients, pagination, nil
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

func (s *Store) CreateClient(client *models.OAuthApplication) error {
	return s.db.Create(client).Error
}

func (s *Store) UpdateClient(client *models.OAuthApplication) error {
	return s.db.Save(client).Error
}

func (s *Store) DeleteClient(clientID string) error {
	return s.db.Where("client_id = ?", clientID).Delete(&models.OAuthApplication{}).Error
}

// Device Code operations

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

// DeleteDeviceCodeByID deletes device code by ID (primary key)
func (s *Store) DeleteDeviceCodeByID(id int64) error {
	return s.db.Delete(&models.DeviceCode{}, id).Error
}

// Access Token operations
func (s *Store) CreateAccessToken(token *models.AccessToken) error {
	return s.db.Create(token).Error
}

func (s *Store) GetAccessToken(token string) (*models.AccessToken, error) {
	var t models.AccessToken
	if err := s.db.Where("token = ?", token).First(&t).Error; err != nil {
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
	offset := (params.Page - 1) * params.PageSize
	if err := query.Order("created_at DESC").
		Limit(params.PageSize).
		Offset(offset).
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

func (s *Store) DeleteExpiredTokens() error {
	return s.db.Where("expires_at < ?", time.Now()).Delete(&models.AccessToken{}).Error
}

func (s *Store) DeleteExpiredDeviceCodes() error {
	return s.db.Where("expires_at < ?", time.Now()).Delete(&models.DeviceCode{}).Error
}

// Health checks the database connection
func (s *Store) Health() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// DB returns the underlying GORM database connection (for transactions)
func (s *Store) DB() *gorm.DB {
	return s.db
}

// UpdateTokenStatus updates the status of a token
func (s *Store) UpdateTokenStatus(tokenID, status string) error {
	return s.db.Model(&models.AccessToken{}).
		Where("id = ?", tokenID).
		Update("status", status).Error
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

// OAuth Connection operations

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

// Audit Log operations

// CreateAuditLog creates a single audit log entry
func (s *Store) CreateAuditLog(log *models.AuditLog) error {
	return s.db.Create(log).Error
}

// CreateAuditLogBatch creates multiple audit log entries in a single transaction
func (s *Store) CreateAuditLogBatch(logs []*models.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	return s.db.CreateInBatches(logs, 100).Error
}

// GetAuditLogsPaginated retrieves audit logs with pagination and filtering
func (s *Store) GetAuditLogsPaginated(
	params PaginationParams,
	filters AuditLogFilters,
) ([]models.AuditLog, PaginationResult, error) {
	var logs []models.AuditLog
	var total int64

	// Build base query
	query := s.db.Model(&models.AuditLog{})

	// Apply filters
	if filters.EventType != "" {
		query = query.Where("event_type = ?", filters.EventType)
	}
	if filters.ActorUserID != "" {
		query = query.Where("actor_user_id = ?", filters.ActorUserID)
	}
	if filters.ResourceType != "" {
		query = query.Where("resource_type = ?", filters.ResourceType)
	}
	if filters.ResourceID != "" {
		query = query.Where("resource_id = ?", filters.ResourceID)
	}
	if filters.Severity != "" {
		query = query.Where("severity = ?", filters.Severity)
	}
	if filters.Success != nil {
		query = query.Where("success = ?", *filters.Success)
	}
	if !filters.StartTime.IsZero() {
		query = query.Where("event_time >= ?", filters.StartTime)
	}
	if !filters.EndTime.IsZero() {
		query = query.Where("event_time <= ?", filters.EndTime)
	}
	if filters.ActorIP != "" {
		query = query.Where("actor_ip = ?", filters.ActorIP)
	}
	if filters.Search != "" {
		searchPattern := "%" + filters.Search + "%"
		query = query.Where(
			"action LIKE ? OR resource_name LIKE ? OR actor_username LIKE ?",
			searchPattern, searchPattern, searchPattern,
		)
	}

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	// Calculate pagination
	pagination := CalculatePagination(total, params.Page, params.PageSize)

	// Apply pagination and fetch results
	offset := (params.Page - 1) * params.PageSize
	if err := query.Order("event_time DESC").
		Limit(params.PageSize).
		Offset(offset).
		Find(&logs).Error; err != nil {
		return nil, PaginationResult{}, err
	}

	return logs, pagination, nil
}

// DeleteOldAuditLogs deletes audit logs older than the specified time
func (s *Store) DeleteOldAuditLogs(olderThan time.Time) (int64, error) {
	result := s.db.Where("created_at < ?", olderThan).Delete(&models.AuditLog{})
	return result.RowsAffected, result.Error
}

// GetAuditLogStats returns statistics about audit logs in a given time range
func (s *Store) GetAuditLogStats(startTime, endTime time.Time) (AuditLogStats, error) {
	stats := AuditLogStats{
		EventsByType:     make(map[models.EventType]int64),
		EventsBySeverity: make(map[models.EventSeverity]int64),
	}

	// Build base query
	query := s.db.Model(&models.AuditLog{})
	if !startTime.IsZero() {
		query = query.Where("event_time >= ?", startTime)
	}
	if !endTime.IsZero() {
		query = query.Where("event_time <= ?", endTime)
	}

	// Total events
	if err := query.Count(&stats.TotalEvents).Error; err != nil {
		return stats, err
	}

	// Success/Failure counts
	if err := query.Where("success = ?", true).Count(&stats.SuccessCount).Error; err != nil {
		return stats, err
	}
	stats.FailureCount = stats.TotalEvents - stats.SuccessCount

	// Events by type
	var typeResults []struct {
		EventType models.EventType
		Count     int64
	}
	if err := query.Select("event_type, COUNT(*) as count").
		Group("event_type").
		Find(&typeResults).Error; err != nil {
		return stats, err
	}
	for _, r := range typeResults {
		stats.EventsByType[r.EventType] = r.Count
	}

	// Events by severity
	var severityResults []struct {
		Severity models.EventSeverity
		Count    int64
	}
	if err := query.Select("severity, COUNT(*) as count").
		Group("severity").
		Find(&severityResults).Error; err != nil {
		return stats, err
	}
	for _, r := range severityResults {
		stats.EventsBySeverity[r.Severity] = r.Count
	}

	return stats, nil
}
