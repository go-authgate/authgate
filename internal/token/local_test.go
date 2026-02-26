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

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
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

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
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

	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredToken)
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

// ============================================================
// GenerateIDToken
// ============================================================

func testIDTokenProvider() (*LocalTokenProvider, *config.Config) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	return NewLocalTokenProvider(cfg), cfg
}

func TestGenerateIDToken_RequiredClaims(t *testing.T) {
	provider, _ := testIDTokenProvider()
	authTime := time.Now().Add(-5 * time.Minute).Truncate(time.Second)

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "user-abc",
		Audience: "client-xyz",
		AuthTime: authTime,
	})

	require.NoError(t, err)
	require.NotEmpty(t, idTokenStr)

	// Parse and verify
	result, err := provider.ValidateToken(context.Background(), idTokenStr)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", result.Claims["iss"])
	assert.Equal(t, "user-abc", result.Claims["sub"])
	assert.Equal(t, "client-xyz", result.Claims["aud"])
	assert.NotNil(t, result.Claims["exp"])
	assert.NotNil(t, result.Claims["iat"])
	assert.InDelta(t, float64(authTime.Unix()), result.Claims["auth_time"].(float64), 1)
	assert.NotEmpty(t, result.Claims["jti"])
}

func TestGenerateIDToken_WithNonce(t *testing.T) {
	provider, _ := testIDTokenProvider()

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "user-abc",
		Audience: "client-xyz",
		AuthTime: time.Now(),
		Nonce:    "random-nonce-value-12345",
	})

	require.NoError(t, err)

	result, err := provider.ValidateToken(context.Background(), idTokenStr)
	require.NoError(t, err)
	assert.Equal(t, "random-nonce-value-12345", result.Claims["nonce"])
}

func TestGenerateIDToken_WithoutNonce_NoClaim(t *testing.T) {
	provider, _ := testIDTokenProvider()

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "user-abc",
		Audience: "client-xyz",
		AuthTime: time.Now(),
		Nonce:    "", // empty – must not appear in token
	})

	require.NoError(t, err)

	result, err := provider.ValidateToken(context.Background(), idTokenStr)
	require.NoError(t, err)
	_, hasNonce := result.Claims["nonce"]
	assert.False(t, hasNonce, "nonce claim must be absent when not provided")
}

func TestGenerateIDToken_WithAtHash(t *testing.T) {
	provider, _ := testIDTokenProvider()
	accessToken := "some.access.token.string"
	expectedAtHash := ComputeAtHash(accessToken)

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "user-abc",
		Audience: "client-xyz",
		AuthTime: time.Now(),
		AtHash:   expectedAtHash,
	})

	require.NoError(t, err)

	result, err := provider.ValidateToken(context.Background(), idTokenStr)
	require.NoError(t, err)
	assert.Equal(t, expectedAtHash, result.Claims["at_hash"])
}

func TestGenerateIDToken_ProfileClaims(t *testing.T) {
	provider, _ := testIDTokenProvider()
	updatedAt := time.Now().Add(-1 * time.Hour).Truncate(time.Second)

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:            "http://localhost:8080",
		Subject:           "user-abc",
		Audience:          "client-xyz",
		AuthTime:          time.Now(),
		Name:              "Jane Doe",
		PreferredUsername: "janedoe",
		Picture:           "https://example.com/avatar.jpg",
		UpdatedAt:         &updatedAt,
	})

	require.NoError(t, err)

	result, err := provider.ValidateToken(context.Background(), idTokenStr)
	require.NoError(t, err)
	assert.Equal(t, "Jane Doe", result.Claims["name"])
	assert.Equal(t, "janedoe", result.Claims["preferred_username"])
	assert.Equal(t, "https://example.com/avatar.jpg", result.Claims["picture"])
	assert.InDelta(t, float64(updatedAt.Unix()), result.Claims["updated_at"].(float64), 1)
}

func TestGenerateIDToken_EmailClaims(t *testing.T) {
	provider, _ := testIDTokenProvider()

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:        "http://localhost:8080",
		Subject:       "user-abc",
		Audience:      "client-xyz",
		AuthTime:      time.Now(),
		Email:         "jane@example.com",
		EmailVerified: false,
	})

	require.NoError(t, err)

	result, err := provider.ValidateToken(context.Background(), idTokenStr)
	require.NoError(t, err)
	assert.Equal(t, "jane@example.com", result.Claims["email"])
	assert.Equal(t, false, result.Claims["email_verified"])
}

func TestGenerateIDToken_NoProfileClaims_WhenEmpty(t *testing.T) {
	provider, _ := testIDTokenProvider()

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "user-abc",
		Audience: "client-xyz",
		AuthTime: time.Now(),
		// No profile or email fields set
	})

	require.NoError(t, err)

	result, err := provider.ValidateToken(context.Background(), idTokenStr)
	require.NoError(t, err)
	_, hasName := result.Claims["name"]
	_, hasEmail := result.Claims["email"]
	_, hasPicture := result.Claims["picture"]
	assert.False(t, hasName)
	assert.False(t, hasEmail)
	assert.False(t, hasPicture)
}

// ============================================================
// ComputeAtHash
// ============================================================

func TestComputeAtHash_Deterministic(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
	hash1 := ComputeAtHash(token)
	hash2 := ComputeAtHash(token)
	assert.Equal(t, hash1, hash2)
	assert.NotEmpty(t, hash1)
}

func TestComputeAtHash_DifferentTokens(t *testing.T) {
	hash1 := ComputeAtHash("token-a")
	hash2 := ComputeAtHash("token-b")
	assert.NotEqual(t, hash1, hash2)
}

func TestComputeAtHash_Length(t *testing.T) {
	// base64url of 16 bytes = 22 chars (no padding)
	hash := ComputeAtHash("any-access-token")
	assert.Len(t, hash, 22)
}

// ============================================================
// ScopeSet
// ============================================================

func TestScopeSet_ParsesCorrectly(t *testing.T) {
	set := ScopeSet("openid profile email")
	assert.True(t, set["openid"])
	assert.True(t, set["profile"])
	assert.True(t, set["email"])
	assert.False(t, set["read"])
}

func TestScopeSet_Empty(t *testing.T) {
	set := ScopeSet("")
	assert.Empty(t, set)
}
