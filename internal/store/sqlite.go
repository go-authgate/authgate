package store

import (
	"crypto/rand"
	"encoding/base64"
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
			ID:           uuid.New().String(),
			Username:     "admin",
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
func (s *Store) CreateDeviceCode(dc *models.DeviceCode) error {
	return s.db.Create(dc).Error
}

func (s *Store) GetDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	var dc models.DeviceCode
	if err := s.db.Where("device_code = ?", deviceCode).First(&dc).Error; err != nil {
		return nil, err
	}
	return &dc, nil
}

func (s *Store) GetDeviceCodeByUserCode(userCode string) (*models.DeviceCode, error) {
	var dc models.DeviceCode
	if err := s.db.Where("user_code = ?", userCode).First(&dc).Error; err != nil {
		return nil, err
	}
	return &dc, nil
}

func (s *Store) UpdateDeviceCode(dc *models.DeviceCode) error {
	return s.db.Save(dc).Error
}

func (s *Store) DeleteDeviceCode(deviceCode string) error {
	return s.db.Where("device_code = ?", deviceCode).Delete(&models.DeviceCode{}).Error
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
