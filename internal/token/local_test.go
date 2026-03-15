package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"

	"github.com/golang-jwt/jwt/v5"
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
// ValidateToken — type checking
// ============================================================

func TestValidateToken_RejectsRefreshToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	// Generate a refresh token
	refreshResult, err := provider.GenerateRefreshToken(
		context.Background(), "user1", "client1", "read",
	)
	require.NoError(t, err)

	// ValidateToken must reject it with a specific message
	_, err = provider.ValidateToken(context.Background(), refreshResult.TokenString)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
	assert.Contains(t, err.Error(), `expected access token, got "refresh"`)
}

func TestValidateToken_RejectsIDToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	// ID tokens have no "type" claim — ValidateToken must reject them
	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "user-abc",
		Audience: "client-xyz",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)

	_, err = provider.ValidateToken(context.Background(), idTokenStr)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
	assert.Contains(t, err.Error(), `expected access token, got ""`)
}

// ============================================================
// ValidateRefreshToken — type checking and error mapping
// ============================================================

func TestValidateRefreshToken_Success(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	genResult, err := provider.GenerateRefreshToken(
		context.Background(), "user1", "client1", "read write",
	)
	require.NoError(t, err)

	valResult, err := provider.ValidateRefreshToken(
		context.Background(), genResult.TokenString,
	)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)
	assert.Equal(t, "user1", valResult.UserID)
	assert.Equal(t, "client1", valResult.ClientID)
	assert.Equal(t, "read write", valResult.Scopes)
}

func TestValidateRefreshToken_RejectsAccessToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	// Generate an access token
	accessResult, err := provider.GenerateToken(
		context.Background(), "user1", "client1", "read",
	)
	require.NoError(t, err)

	// ValidateRefreshToken must reject it with a specific message
	_, err = provider.ValidateRefreshToken(
		context.Background(), accessResult.TokenString,
	)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.Contains(t, err.Error(), `expected refresh token, got "access"`)
}

func TestValidateRefreshToken_ExpiredReturnsRefreshError(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 1 * time.Millisecond, // Very short
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	genResult, err := provider.GenerateRefreshToken(
		context.Background(), "user1", "client1", "read",
	)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	// Must return ErrExpiredRefreshToken, not ErrExpiredToken
	_, err = provider.ValidateRefreshToken(
		context.Background(), genResult.TokenString,
	)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredRefreshToken)
}

func TestValidateRefreshToken_InvalidReturnsRefreshError(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	// Must return ErrInvalidRefreshToken, not ErrInvalidToken
	_, err := provider.ValidateRefreshToken(
		context.Background(), "garbage-token",
	)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidRefreshToken)
}

// ============================================================
// mapRefreshError
// ============================================================

func TestMapRefreshError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{
			"expired token maps to expired refresh token",
			ErrExpiredToken,
			ErrExpiredRefreshToken,
		},
		{
			"invalid token maps to invalid refresh token",
			ErrInvalidToken,
			ErrInvalidRefreshToken,
		},
		{
			"wrapped expired token maps correctly",
			fmt.Errorf("something: %w", ErrExpiredToken),
			ErrExpiredRefreshToken,
		},
		{
			"wrapped invalid token maps correctly",
			fmt.Errorf("something: %w", ErrInvalidToken),
			ErrInvalidRefreshToken,
		},
		{
			"unrelated error passes through",
			ErrTokenGeneration,
			ErrTokenGeneration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapRefreshError(tt.input)
			assert.ErrorIs(t, result, tt.expected)
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

// parseIDTokenClaims is a test helper that parses an ID token JWT and returns its claims.
// ID tokens don't have a "type" claim, so we use ParseJWT directly (no type check).
func parseIDTokenClaims(
	t *testing.T,
	provider *LocalTokenProvider,
	tokenStr string,
) map[string]any {
	t.Helper()
	result, err := provider.ParseJWT(tokenStr)
	require.NoError(t, err)
	return result.Claims
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
	claims := parseIDTokenClaims(t, provider, idTokenStr)
	assert.Equal(t, "http://localhost:8080", claims["iss"])
	assert.Equal(t, "user-abc", claims["sub"])
	assert.Equal(t, "client-xyz", claims["aud"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
	assert.InDelta(t, float64(authTime.Unix()), claims["auth_time"].(float64), 1)
	assert.NotEmpty(t, claims["jti"])
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

	claims := parseIDTokenClaims(t, provider, idTokenStr)
	assert.Equal(t, "random-nonce-value-12345", claims["nonce"])
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

	claims := parseIDTokenClaims(t, provider, idTokenStr)
	_, hasNonce := claims["nonce"]
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

	claims := parseIDTokenClaims(t, provider, idTokenStr)
	assert.Equal(t, expectedAtHash, claims["at_hash"])
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

	claims := parseIDTokenClaims(t, provider, idTokenStr)
	assert.Equal(t, "Jane Doe", claims["name"])
	assert.Equal(t, "janedoe", claims["preferred_username"])
	assert.Equal(t, "https://example.com/avatar.jpg", claims["picture"])
	assert.InDelta(t, float64(updatedAt.Unix()), claims["updated_at"].(float64), 1)
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

	claims := parseIDTokenClaims(t, provider, idTokenStr)
	assert.Equal(t, "jane@example.com", claims["email"])
	assert.Equal(t, false, claims["email_verified"])
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

	claims := parseIDTokenClaims(t, provider, idTokenStr)
	_, hasName := claims["name"]
	_, hasEmail := claims["email"]
	_, hasPicture := claims["picture"]
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
// RS256 / ES256 tests
// ============================================================

func TestLocalTokenProvider_RS256_GenerateAndValidate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := &config.Config{
		JWTSigningAlgorithm:    "RS256",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("test-rsa-kid"),
	)

	result, err := provider.GenerateToken(context.Background(), "user1", "client1", "read write")
	require.NoError(t, err)
	assert.NotEmpty(t, result.TokenString)

	valResult, err := provider.ValidateToken(context.Background(), result.TokenString)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)
	assert.Equal(t, "user1", valResult.UserID)
	assert.Equal(t, "client1", valResult.ClientID)
	assert.Equal(t, "read write", valResult.Scopes)
}

func TestLocalTokenProvider_ES256_GenerateAndValidate(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cfg := &config.Config{
		JWTSigningAlgorithm:    "ES256",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg,
		WithSigningKey(ecKey, &ecKey.PublicKey),
		WithKeyID("test-ec-kid"),
	)

	result, err := provider.GenerateToken(context.Background(), "user2", "client2", "email")
	require.NoError(t, err)
	assert.NotEmpty(t, result.TokenString)

	valResult, err := provider.ValidateToken(context.Background(), result.TokenString)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)
	assert.Equal(t, "user2", valResult.UserID)
}

func TestLocalTokenProvider_RS256_IDToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("rsa-kid"),
	)

	idTokenStr, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "user-abc",
		Audience: "client-xyz",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, idTokenStr)

	// Parse and verify
	claims := parseIDTokenClaims(t, provider, idTokenStr)
	assert.Equal(t, "http://localhost:8080", claims["iss"])
	assert.Equal(t, "user-abc", claims["sub"])
}

func TestLocalTokenProvider_HS256_BackwardCompatible(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	// No options — pure HS256 backward compatibility
	provider := NewLocalTokenProvider(cfg)

	// Access token
	result, err := provider.GenerateToken(context.Background(), "u1", "c1", "r")
	require.NoError(t, err)
	valResult, err := provider.ValidateToken(context.Background(), result.TokenString)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)

	// Refresh token
	refreshResult, err := provider.GenerateRefreshToken(context.Background(), "u1", "c1", "r")
	require.NoError(t, err)
	refreshVal, err := provider.ValidateRefreshToken(
		context.Background(),
		refreshResult.TokenString,
	)
	require.NoError(t, err)
	assert.True(t, refreshVal.Valid)

	// ID token
	idToken, err := provider.GenerateIDToken(IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  "u1",
		Audience: "c1",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, idToken)
}

func TestLocalTokenProvider_KidHeader(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("my-kid-123"),
	)

	result, err := provider.GenerateToken(context.Background(), "user1", "client1", "read")
	require.NoError(t, err)

	// Parse the raw JWT to inspect header
	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(result.TokenString, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, "my-kid-123", tok.Header["kid"])
	assert.Equal(t, "RS256", tok.Header["alg"])
}

func TestLocalTokenProvider_HS256_NoKidHeader(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	result, err := provider.GenerateToken(context.Background(), "user1", "client1", "read")
	require.NoError(t, err)

	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(result.TokenString, jwt.MapClaims{})
	require.NoError(t, err)
	_, hasKid := tok.Header["kid"]
	assert.False(t, hasKid, "HS256 tokens should not have a kid header")
}

func TestLocalTokenProvider_RS256_CrossValidationFails(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}

	provider1 := NewLocalTokenProvider(cfg,
		WithSigningKey(key1, &key1.PublicKey),
	)
	provider2 := NewLocalTokenProvider(cfg,
		WithSigningKey(key2, &key2.PublicKey),
	)

	result, err := provider1.GenerateToken(context.Background(), "u", "c", "r")
	require.NoError(t, err)

	_, err = provider2.ValidateToken(context.Background(), result.TokenString)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestLocalTokenProvider_RS256_RefreshToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cfg := &config.Config{
		JWTSigningAlgorithm:    "RS256",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		EnableTokenRotation:    true,
		BaseURL:                "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
	)

	refreshResult, err := provider.GenerateRefreshToken(context.Background(), "u1", "c1", "r")
	require.NoError(t, err)

	valResult, err := provider.ValidateRefreshToken(context.Background(), refreshResult.TokenString)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)
	assert.Equal(t, "u1", valResult.UserID)

	// RefreshAccessToken
	refreshed, err := provider.RefreshAccessToken(context.Background(), refreshResult.TokenString)
	require.NoError(t, err)
	assert.NotNil(t, refreshed.AccessToken)
	assert.NotNil(t, refreshed.RefreshToken, "rotation mode should produce new refresh token")
}

func TestLocalTokenProvider_PublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("kid1"),
	)

	assert.Equal(t, &rsaKey.PublicKey, provider.PublicKey())
	assert.Equal(t, "kid1", provider.KeyID())
	assert.Equal(t, "RS256", provider.Algorithm())
}

func TestLocalTokenProvider_HS256_PublicKey_Nil(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider := NewLocalTokenProvider(cfg)

	assert.Nil(t, provider.PublicKey())
	assert.Empty(t, provider.KeyID())
	assert.Equal(t, "HS256", provider.Algorithm())
}
