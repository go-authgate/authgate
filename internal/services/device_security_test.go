package services

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestService(t *testing.T) (*DeviceService, *models.OAuthApplication) {
	cfg := &config.Config{
		DefaultAdminPassword: "", // Use random password in tests
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}

	st, err := store.New(context.Background(), "sqlite", ":memory:", cfg)
	require.NoError(t, err)
	service := NewDeviceService(st, cfg, nil, metrics.NewNoopMetrics())

	// Create test client
	client := &models.OAuthApplication{
		ClientID:         "test-client-id",
		ClientName:       "Test Client",
		RedirectURIs:     models.StringArray{},
		EnableDeviceFlow: true,
		IsActive:         true,
	}
	err = st.CreateClient(client)
	require.NoError(t, err)

	return service, client
}

func TestDeviceCodeHashing(t *testing.T) {
	service, client := setupTestService(t)

	t.Run("DeviceCode field not stored in database", func(t *testing.T) {
		dc, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)
		assert.NotEmpty(t, dc.DeviceCode, "DeviceCode field should be populated")
		assert.Len(t, dc.DeviceCode, 40, "DeviceCode should be 40 hex chars")

		// Query database directly - should not find plaintext
		var dbRecord models.DeviceCode
		err = service.store.DB().Where("device_code_id = ?", dc.DeviceCodeID).First(&dbRecord).Error
		require.NoError(t, err)
		assert.Empty(t, dbRecord.DeviceCode, "DeviceCode should not exist in database")
		assert.NotEmpty(t, dbRecord.DeviceCodeHash, "Hash should exist")
		assert.NotEmpty(t, dbRecord.DeviceCodeSalt, "Salt should exist")
	})

	t.Run("Valid device code passes verification", func(t *testing.T) {
		dc, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)
		plaintext := dc.DeviceCode

		// Verify
		retrieved, err := service.GetDeviceCode(plaintext)
		require.NoError(t, err)
		assert.Equal(t, dc.UserCode, retrieved.UserCode)
		assert.Equal(t, plaintext, retrieved.DeviceCode)
	})

	t.Run("Invalid device code fails verification", func(t *testing.T) {
		dc, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)

		// Try with wrong code (same suffix, different prefix)
		wrongCode := "0000000000000000000000000000000" + dc.DeviceCodeID
		_, err = service.GetDeviceCode(wrongCode)
		assert.Equal(t, ErrDeviceCodeNotFound, err)
	})

	t.Run("Hash collision does not grant access", func(t *testing.T) {
		// Generate two codes
		dc1, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)

		dc2, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)

		// Try to use dc1's prefix with dc2's suffix
		fakeCode := dc1.DeviceCode[:32] + dc2.DeviceCodeID
		_, err = service.GetDeviceCode(fakeCode)
		assert.Error(t, err)
	})
}

func TestDeviceCodeInputValidation(t *testing.T) {
	service, client := setupTestService(t)

	t.Run("Valid 40-char hex code passes", func(t *testing.T) {
		dc, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)

		retrieved, err := service.GetDeviceCode(dc.DeviceCode)
		require.NoError(t, err)
		assert.NotNil(t, retrieved)
	})

	t.Run("Invalid length rejected", func(t *testing.T) {
		testCases := []struct {
			name string
			code string
		}{
			{"Empty", ""},
			{"Too short", "abc"},
			{"39 chars", "0123456789abcdef0123456789abcdef01234"},
			{"41 chars", "0123456789abcdef0123456789abcdef012345"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.GetDeviceCode(tc.code)
				assert.Equal(t, ErrDeviceCodeNotFound, err)
			})
		}
	})

	t.Run("Non-hex characters rejected", func(t *testing.T) {
		testCases := []struct {
			name string
			code string
		}{
			{"Uppercase", "0123456789ABCDEF0123456789ABCDEF01234567"},
			{"Invalid char 'g'", "0123456789abcdefg123456789abcdef01234567"},
			{"Space", "0123456789abcdef 123456789abcdef01234567"},
			{"Dash", "0123456789abcdef-123456789abcdef01234567"},
			{"Special chars", "<script>alert('xss')</script>0000000000"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.GetDeviceCode(tc.code)
				assert.Equal(t, ErrDeviceCodeNotFound, err)
			})
		}
	})
}

func TestConstantTimeComparison(t *testing.T) {
	const testHash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"

	t.Run("Constant-time comparison correctness", func(t *testing.T) {
		hash1 := testHash
		hash2 := testHash
		hash3 := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

		// Same hashes should match
		result1 := subtle.ConstantTimeCompare([]byte(hash1), []byte(hash2))
		assert.Equal(t, 1, result1, "Identical hashes should match")

		// Different hashes should not match
		result2 := subtle.ConstantTimeCompare([]byte(hash1), []byte(hash3))
		assert.Equal(t, 0, result2, "Different hashes should not match")
	})

	t.Run("Timing consistency check", func(t *testing.T) {
		// This is a basic sanity check - real timing attack analysis requires
		// statistical analysis over many iterations with proper benchmarking setup
		hash := testHash
		almostMatch := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789000000000000000000000000000000000000"
		noMatch := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

		iterations := 100000 // More iterations for better averaging

		// Warm up
		for range 1000 {
			subtle.ConstantTimeCompare([]byte(hash), []byte(almostMatch))
		}

		start1 := time.Now()
		for range iterations {
			subtle.ConstantTimeCompare([]byte(hash), []byte(almostMatch))
		}
		duration1 := time.Since(start1)

		start2 := time.Now()
		for range iterations {
			subtle.ConstantTimeCompare([]byte(hash), []byte(noMatch))
		}
		duration2 := time.Since(start2)

		// Both operations should complete (this is more of a smoke test)
		// We mainly trust Go's crypto/subtle package's constant-time guarantees
		assert.Greater(t, duration1, time.Duration(0))
		assert.Greater(t, duration2, time.Duration(0))

		// Log the timing for informational purposes
		t.Logf("Timing info: almostMatch=%v, noMatch=%v", duration1, duration2)
	})
}

func TestDeviceCodeGeneration(t *testing.T) {
	service, client := setupTestService(t)

	t.Run("Generated codes are unique", func(t *testing.T) {
		codes := make(map[string]bool)

		for range 100 {
			dc, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
			require.NoError(t, err)

			assert.False(t, codes[dc.DeviceCode], "Duplicate device code generated")
			codes[dc.DeviceCode] = true
		}
	})

	t.Run("Generated codes have correct format", func(t *testing.T) {
		dc, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)

		// Check length
		assert.Len(t, dc.DeviceCode, 40)

		// Check hex format
		_, err = hex.DecodeString(dc.DeviceCode)
		require.NoError(t, err, "DeviceCode should be valid hex")

		// Check DeviceCodeID is last 8 chars
		assert.Equal(t, dc.DeviceCode[32:], dc.DeviceCodeID)
	})

	t.Run("Hash and salt are properly generated", func(t *testing.T) {
		dc, err := service.GenerateDeviceCode(context.Background(), client.ClientID, "read")
		require.NoError(t, err)

		// Check hash length (50 bytes = 100 hex chars)
		assert.Len(t, dc.DeviceCodeHash, 100)

		// Check salt length (20 chars)
		assert.Len(t, dc.DeviceCodeSalt, 20)

		// Verify hash can be reproduced
		expectedHash := util.HashToken(dc.DeviceCode, dc.DeviceCodeSalt)
		assert.Equal(t, expectedHash, dc.DeviceCodeHash)
	})
}
