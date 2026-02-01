package services

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/util"
)

var (
	ErrInvalidClient      = errors.New("invalid client_id")
	ErrClientInactive     = errors.New("client is inactive")
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
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// Check if client is active
	if !client.IsActive {
		return nil, ErrClientInactive
	}

	// Generate cryptographically secure device code (20 bytes = 40 hex chars)
	codeBytes, err := util.CryptoRandomBytes(20)
	if err != nil {
		return nil, fmt.Errorf("failed to generate device code: %w", err)
	}
	deviceCodePlaintext := hex.EncodeToString(codeBytes)

	// Generate salt (20 hex chars)
	salt, err := util.CryptoRandomString(20)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Calculate hash and ID
	deviceCodeHash := util.HashToken(deviceCodePlaintext, salt)
	deviceCodeID := deviceCodePlaintext[len(deviceCodePlaintext)-8:] // Last 8 chars for indexing

	deviceCode := &models.DeviceCode{
		DeviceCode:     deviceCodePlaintext, // Set in struct but not saved to DB (gorm:"-")
		DeviceCodeHash: deviceCodeHash,
		DeviceCodeSalt: salt,
		DeviceCodeID:   deviceCodeID,
		UserCode:       generateUserCode(),
		ClientID:       clientID,
		Scopes:         scope,
		ExpiresAt:      time.Now().Add(s.config.DeviceCodeExpiration),
		Interval:       s.config.PollingInterval,
		Authorized:     false,
	}

	if err := s.store.CreateDeviceCode(deviceCode); err != nil {
		return nil, err
	}

	return deviceCode, nil
}

// GetDeviceCode retrieves a device code by its code
func (s *DeviceService) GetDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	// 1. Validate device code length (40 hex characters)
	if len(deviceCode) != 40 {
		return nil, ErrDeviceCodeNotFound
	}

	// 2. Validate hex characters only (prevents injection and invalid input)
	for _, x := range []byte(deviceCode) {
		if x < '0' || (x > '9' && x < 'a') || x > 'f' {
			return nil, ErrDeviceCodeNotFound
		}
	}

	// 3. Extract device code ID (last 8 chars) for indexed lookup
	deviceCodeID := deviceCode[len(deviceCode)-8:]

	// 4. Get all candidates with matching ID suffix
	candidates, err := s.store.GetDeviceCodesByID(deviceCodeID)
	if err != nil {
		return nil, ErrDeviceCodeNotFound
	}

	// 5. Verify hash for each candidate using constant-time comparison
	for _, dc := range candidates {
		tempHash := util.HashToken(deviceCode, dc.DeviceCodeSalt)

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(dc.DeviceCodeHash), []byte(tempHash)) == 1 {
			// Check expiration
			if dc.IsExpired() {
				_ = s.store.DeleteDeviceCodeByID(dc.ID)
				return nil, ErrDeviceCodeExpired
			}

			// Fill plaintext field for business logic use (not saved to DB)
			dc.DeviceCode = deviceCode
			return dc, nil
		}
	}

	return nil, ErrDeviceCodeNotFound
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
		_ = s.store.DeleteDeviceCodeByID(dc.ID)
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

// GetClientNameByUserCode retrieves the client name associated with a user code
func (s *DeviceService) GetClientNameByUserCode(userCode string) (string, error) {
	dc, err := s.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		return "", err
	}

	client, err := s.store.GetClient(dc.ClientID)
	if err != nil {
		return "", err
	}

	return client.ClientName, nil
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
