package token

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalTokenProvider_GenerateToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	result, err := provider.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
	)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.NotEmpty(t, result.TokenString)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.WithinDuration(t, time.Now().Add(1*time.Hour), result.ExpiresAt, 5*time.Second)
	assert.NotNil(t, result.Claims)
	assert.Equal(t, "user123", result.Claims["user_id"])
	assert.Equal(t, "client456", result.Claims["client_id"])
	assert.Equal(t, "read write", result.Claims["scope"])
}

func TestLocalTokenProvider_ValidateToken_Success(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	// Generate a token first
	genResult, err := provider.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
	)
	require.NoError(t, err)

	// Validate the token
	valResult, err := provider.ValidateToken(
		context.Background(),
		genResult.TokenString,
	)

	require.NoError(t, err)
	assert.True(t, valResult.Valid)
	assert.Equal(t, "user123", valResult.UserID)
	assert.Equal(t, "client456", valResult.ClientID)
	assert.Equal(t, "read write", valResult.Scopes)
	assert.WithinDuration(t, time.Now().Add(1*time.Hour), valResult.ExpiresAt, 5*time.Second)
	assert.NotNil(t, valResult.Claims)
}

func TestLocalTokenProvider_ValidateToken_InvalidToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	// Try to validate an invalid token
	_, err := provider.ValidateToken(
		context.Background(),
		"invalid-token-string",
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestLocalTokenProvider_ValidateToken_WrongSecret(t *testing.T) {
	// Generate token with one secret
	cfg1 := &config.Config{
		JWTSecret:     "secret1",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider1 := NewLocalTokenProvider(cfg1)
	genResult, err := provider1.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
	)
	require.NoError(t, err)

	// Try to validate with different secret
	cfg2 := &config.Config{
		JWTSecret:     "secret2",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider2 := NewLocalTokenProvider(cfg2)
	_, err = provider2.ValidateToken(
		context.Background(),
		genResult.TokenString,
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestLocalTokenProvider_ValidateToken_ExpiredToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Millisecond, // Very short expiration
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	// Generate token
	genResult, err := provider.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
	)
	require.NoError(t, err)

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	// Try to validate expired token
	_, err = provider.ValidateToken(
		context.Background(),
		genResult.TokenString,
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExpiredToken)
}

func TestLocalTokenProvider_Name(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	assert.Equal(t, "local", provider.Name())
}

func TestLocalTokenProvider_GenerateToken_VariousExpirations(t *testing.T) {
	tests := []struct {
		name       string
		expiration time.Duration
	}{
		{"1 hour", 1 * time.Hour},
		{"24 hours", 24 * time.Hour},
		{"1 minute", 1 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				JWTSecret:     "test-secret",
				JWTExpiration: tt.expiration,
				BaseURL:       "http://localhost:8080",
			}
			provider := NewLocalTokenProvider(cfg)

			result, err := provider.GenerateToken(
				context.Background(),
				"user123",
				"client456",
				"read",
			)

			require.NoError(t, err)
			expectedExpiry := time.Now().Add(tt.expiration)
			assert.WithinDuration(t, expectedExpiry, result.ExpiresAt, 1*time.Second)
		})
	}
}
