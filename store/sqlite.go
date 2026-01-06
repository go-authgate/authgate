package store

import (
	"log"

	"oauth-device-flow/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Store struct {
	db *gorm.DB
}

func New(dbPath string) (*Store, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
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

func (s *Store) seedData() error {
	// Create default user if not exists
	var userCount int64
	s.db.Model(&models.User{}).Count(&userCount)
	if userCount == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user := &models.User{
			ID:           uuid.New().String(),
			Username:     "admin",
			PasswordHash: string(hash),
		}
		if err := s.db.Create(user).Error; err != nil {
			return err
		}
		log.Println("Created default user: admin / password123")
	}

	// Create default OAuth client if not exists
	var clientCount int64
	s.db.Model(&models.OAuthClient{}).Count(&clientCount)
	if clientCount == 0 {
		client := &models.OAuthClient{
			ClientID:   "cli-tool",
			ClientName: "CLI Tool",
			Scopes:     "read write",
		}
		if err := s.db.Create(client).Error; err != nil {
			return err
		}
		log.Println("Created default OAuth client: cli-tool")
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

func (s *Store) DeleteExpiredTokens() error {
	return s.db.Where("expires_at < datetime('now')").Delete(&models.AccessToken{}).Error
}

func (s *Store) DeleteExpiredDeviceCodes() error {
	return s.db.Where("expires_at < datetime('now')").Delete(&models.DeviceCode{}).Error
}
