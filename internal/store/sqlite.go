package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/appleboy/authgate/internal/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Store struct {
	db *gorm.DB
}

func New(driver, dsn string) (*Store, error) {
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
		&models.OAuthClient{},
		&models.DeviceCode{},
		&models.AccessToken{},
		&models.OAuthConnection{},
	); err != nil {
		return nil, err
	}

	store := &Store{db: db}

	// Seed default data
	if err := store.seedData(); err != nil {
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

func (s *Store) seedData() error {
	// Create default user if not exists
	var userCount int64
	s.db.Model(&models.User{}).Count(&userCount)
	userID := uuid.New().String()
	if userCount == 0 {
		// Generate random password
		password, err := generateRandomPassword(16)
		if err != nil {
			return err
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
		log.Printf("Created default user: admin / %s (role: admin)", password)
	}

	// Create default OAuth client if not exists
	var clientCount int64
	s.db.Model(&models.OAuthClient{}).Count(&clientCount)
	if clientCount == 0 {
		clientID := uuid.New().String()
		clientSecret := uuid.New().String()
		secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		client := &models.OAuthClient{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: string(secretHash),
			ClientName:   "AuthGate CLI",
			Description:  "Default CLI client for device authorization flow",
			Scopes:       "read write",
			GrantTypes:   "device_code",
			IsActive:     true,
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
func (s *Store) GetClient(clientID string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	if err := s.db.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *Store) ListClients() ([]models.OAuthClient, error) {
	var clients []models.OAuthClient
	if err := s.db.Order("created_at DESC").Find(&clients).Error; err != nil {
		return nil, err
	}
	return clients, nil
}

func (s *Store) GetClientsByIDs(clientIDs []string) (map[string]*models.OAuthClient, error) {
	if len(clientIDs) == 0 {
		return make(map[string]*models.OAuthClient), nil
	}

	var clients []models.OAuthClient
	if err := s.db.Where("client_id IN ?", clientIDs).Find(&clients).Error; err != nil {
		return nil, err
	}

	// Convert to map for easy lookup
	clientMap := make(map[string]*models.OAuthClient, len(clients))
	for i := range clients {
		clientMap[clients[i].ClientID] = &clients[i]
	}

	return clientMap, nil
}

func (s *Store) CreateClient(client *models.OAuthClient) error {
	return s.db.Create(client).Error
}

func (s *Store) UpdateClient(client *models.OAuthClient) error {
	return s.db.Save(client).Error
}

func (s *Store) DeleteClient(clientID string) error {
	return s.db.Where("client_id = ?", clientID).Delete(&models.OAuthClient{}).Error
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
