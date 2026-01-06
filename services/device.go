package services

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/appleboy/authgate/config"
	"github.com/appleboy/authgate/models"
	"github.com/appleboy/authgate/store"

	"github.com/google/uuid"
)

var (
	ErrInvalidClient      = errors.New("invalid client_id")
	ErrDeviceCodeNotFound = errors.New("device code not found")
	ErrDeviceCodeExpired  = errors.New("device code expired")
	ErrUserCodeNotFound   = errors.New("user code not found")
)

type DeviceService struct {
	store  *store.Store
	config *config.Config
}

func NewDeviceService(s *store.Store, cfg *config.Config) *DeviceService {
	return &DeviceService{store: s, config: cfg}
}

// GenerateDeviceCode creates a new device code request
func (s *DeviceService) GenerateDeviceCode(clientID, scope string) (*models.DeviceCode, error) {
	// Validate client
	_, err := s.store.GetClient(clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	deviceCode := &models.DeviceCode{
		DeviceCode: uuid.New().String(),
		UserCode:   generateUserCode(),
		ClientID:   clientID,
		Scopes:     scope,
		ExpiresAt:  time.Now().Add(s.config.DeviceCodeExpiration),
		Interval:   s.config.PollingInterval,
		Authorized: false,
	}

	if err := s.store.CreateDeviceCode(deviceCode); err != nil {
		return nil, err
	}

	return deviceCode, nil
}

// GetDeviceCode retrieves a device code by its code
func (s *DeviceService) GetDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	dc, err := s.store.GetDeviceCode(deviceCode)
	if err != nil {
		return nil, ErrDeviceCodeNotFound
	}

	if dc.IsExpired() {
		_ = s.store.DeleteDeviceCode(deviceCode)
		return nil, ErrDeviceCodeExpired
	}

	return dc, nil
}

// GetDeviceCodeByUserCode retrieves a device code by user code
func (s *DeviceService) GetDeviceCodeByUserCode(userCode string) (*models.DeviceCode, error) {
	// Normalize user code (uppercase, remove dashes)
	userCode = strings.ToUpper(strings.ReplaceAll(userCode, "-", ""))

	dc, err := s.store.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		return nil, ErrUserCodeNotFound
	}

	if dc.IsExpired() {
		_ = s.store.DeleteDeviceCode(dc.DeviceCode)
		return nil, ErrDeviceCodeExpired
	}

	return dc, nil
}

// AuthorizeDeviceCode marks a device code as authorized by a user
func (s *DeviceService) AuthorizeDeviceCode(userCode, userID string) error {
	dc, err := s.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		return err
	}

	dc.UserID = userID
	dc.Authorized = true
	dc.AuthorizedAt = time.Now()

	return s.store.UpdateDeviceCode(dc)
}

// generateUserCode creates a user-friendly code like "ABCD-EFGH"
// Avoids confusing characters: 0, O, 1, I, L
func generateUserCode() string {
	const charset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	code := make([]byte, 8)

	for i := range code {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		code[i] = charset[n.Int64()]
	}

	// Format as XXXX-XXXX but store without dash
	return string(code)
}

// FormatUserCode formats a user code for display (e.g., "ABCDEFGH" -> "ABCD-EFGH")
func FormatUserCode(code string) string {
	if len(code) != 8 {
		return code
	}
	return code[:4] + "-" + code[4:]
}
