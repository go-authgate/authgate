package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shared test keys generated once per package to avoid repeated 2048-bit RSA key generation.
var (
	testRSAKey     *rsa.PrivateKey
	testRSAKeyErr  error
	testRSAOnce    sync.Once
	testRSAKey2    *rsa.PrivateKey
	testRSAKey2Err error
	testRSAOnce2   sync.Once
	testECKey      *ecdsa.PrivateKey
	testECKeyErr   error
	testECOnce     sync.Once
)

func getTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() {
		testRSAKey, testRSAKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	require.NoError(t, testRSAKeyErr)
	return testRSAKey
}

func getTestRSAKey2(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce2.Do(func() {
		testRSAKey2, testRSAKey2Err = rsa.GenerateKey(rand.Reader, 2048)
	})
	require.NoError(t, testRSAKey2Err)
	return testRSAKey2
}

func getTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	testECOnce.Do(func() {
		testECKey, testECKeyErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	require.NoError(t, testECKeyErr)
	return testECKey
}

func TestLocalTokenProvider_GenerateToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	result, err := provider.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
		0, nil, nil)

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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Generate a token first
	genResult, err := provider.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
		0, nil, nil)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Try to validate an invalid token
	_, err = provider.ValidateToken(
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
	provider1, err := NewLocalTokenProvider(cfg1)
	require.NoError(t, err)
	genResult, err := provider1.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
		0, nil, nil)
	require.NoError(t, err)

	// Try to validate with different secret
	cfg2 := &config.Config{
		JWTSecret:     "secret2",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider2, err := NewLocalTokenProvider(cfg2)
	require.NoError(t, err)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Generate token
	genResult, err := provider.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
		0, nil, nil)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

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
			provider, err := NewLocalTokenProvider(cfg)
			require.NoError(t, err)

			result, err := provider.GenerateToken(
				context.Background(),
				"user123",
				"client456",
				"read",
				0, nil, nil)

			require.NoError(t, err)
			expectedExpiry := time.Now().Add(tt.expiration)
			assert.WithinDuration(t, expectedExpiry, result.ExpiresAt, 1*time.Second)
		})
	}
}

// An explicit ttl > 0 must override the config default and skip jitter so that
// per-client TokenProfile values are honored exactly.
func TestLocalTokenProvider_GenerateToken_TTLOverride(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:           "test-secret-that-is-at-least-32b",
		JWTExpiration:       10 * time.Hour,   // config default
		JWTExpirationJitter: 30 * time.Minute, // jitter only applies to default
		BaseURL:             "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Explicit 15-minute TTL must be applied verbatim (no jitter, no config).
	// Capture start before token generation so the assertion is robust on
	// slower CI runners where time.Now() can drift between the two calls.
	start := time.Now()
	result, err := provider.GenerateToken(
		context.Background(), "u", "c", "s", 15*time.Minute, nil, nil)
	require.NoError(t, err)
	assert.WithinDuration(t, start.Add(15*time.Minute), result.ExpiresAt, 2*time.Second)
}

func TestLocalTokenProvider_GenerateRefreshToken_TTLOverride(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-that-is-at-least-32b",
		JWTExpiration:          time.Hour,
		RefreshTokenExpiration: 720 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	start := time.Now()
	result, err := provider.GenerateRefreshToken(
		context.Background(), "u", "c", "s", 24*time.Hour, nil, nil)
	require.NoError(t, err)
	assert.WithinDuration(t, start.Add(24*time.Hour), result.ExpiresAt, 2*time.Second)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Generate a refresh token
	refreshResult, err := provider.GenerateRefreshToken(
		context.Background(), "user1", "client1", "read", 0, nil, nil)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	genResult, err := provider.GenerateRefreshToken(
		context.Background(), "user1", "client1", "read write", 0, nil, nil)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Generate an access token
	accessResult, err := provider.GenerateToken(
		context.Background(), "user1", "client1", "read", 0, nil, nil)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	genResult, err := provider.GenerateRefreshToken(
		context.Background(), "user1", "client1", "read", 0, nil, nil)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Must return ErrInvalidRefreshToken, not ErrInvalidToken
	_, err = provider.ValidateRefreshToken(
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

func testIDTokenProvider(t *testing.T) (*LocalTokenProvider, *config.Config) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	p, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	return p, cfg
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
	provider, _ := testIDTokenProvider(t)
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
	provider, _ := testIDTokenProvider(t)

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
	provider, _ := testIDTokenProvider(t)

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
	provider, _ := testIDTokenProvider(t)
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
	provider, _ := testIDTokenProvider(t)
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
	provider, _ := testIDTokenProvider(t)

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
	provider, _ := testIDTokenProvider(t)

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
	rsaKey := getTestRSAKey(t)

	cfg := &config.Config{
		JWTSigningAlgorithm:    "RS256",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("test-rsa-kid"),
	)
	require.NoError(t, err)

	result, err := provider.GenerateToken(
		context.Background(),
		"user1",
		"client1",
		"read write",
		0,
		nil,
		nil,
	)
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
	ecKey := getTestECKey(t)

	cfg := &config.Config{
		JWTSigningAlgorithm:    "ES256",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg,
		WithSigningKey(ecKey, &ecKey.PublicKey),
		WithKeyID("test-ec-kid"),
	)
	require.NoError(t, err)

	result, err := provider.GenerateToken(
		context.Background(),
		"user2",
		"client2",
		"email",
		0,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, result.TokenString)

	valResult, err := provider.ValidateToken(context.Background(), result.TokenString)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)
	assert.Equal(t, "user2", valResult.UserID)
}

func TestLocalTokenProvider_RS256_IDToken(t *testing.T) {
	rsaKey := getTestRSAKey(t)

	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("rsa-kid"),
	)
	require.NoError(t, err)

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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Access token
	result, err := provider.GenerateToken(context.Background(), "u1", "c1", "r", 0, nil, nil)
	require.NoError(t, err)
	valResult, err := provider.ValidateToken(context.Background(), result.TokenString)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)

	// Refresh token
	refreshResult, err := provider.GenerateRefreshToken(
		context.Background(),
		"u1",
		"c1",
		"r",
		0,
		nil,
		nil,
	)
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
	rsaKey := getTestRSAKey(t)

	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("my-kid-123"),
	)
	require.NoError(t, err)

	result, err := provider.GenerateToken(
		context.Background(),
		"user1",
		"client1",
		"read",
		0,
		nil,
		nil,
	)
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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	result, err := provider.GenerateToken(
		context.Background(),
		"user1",
		"client1",
		"read",
		0,
		nil,
		nil,
	)
	require.NoError(t, err)

	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(result.TokenString, jwt.MapClaims{})
	require.NoError(t, err)
	_, hasKid := tok.Header["kid"]
	assert.False(t, hasKid, "HS256 tokens should not have a kid header")
}

func TestLocalTokenProvider_RS256_CrossValidationFails(t *testing.T) {
	key1 := getTestRSAKey(t)
	key2 := getTestRSAKey2(t)

	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}

	provider1, err := NewLocalTokenProvider(cfg,
		WithSigningKey(key1, &key1.PublicKey),
	)
	require.NoError(t, err)
	provider2, err := NewLocalTokenProvider(cfg,
		WithSigningKey(key2, &key2.PublicKey),
	)
	require.NoError(t, err)

	result, err := provider1.GenerateToken(context.Background(), "u", "c", "r", 0, nil, nil)
	require.NoError(t, err)

	_, err = provider2.ValidateToken(context.Background(), result.TokenString)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestLocalTokenProvider_RS256_RefreshToken(t *testing.T) {
	rsaKey := getTestRSAKey(t)
	cfg := &config.Config{
		JWTSigningAlgorithm:    "RS256",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		EnableTokenRotation:    true,
		BaseURL:                "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
	)
	require.NoError(t, err)

	refreshResult, err := provider.GenerateRefreshToken(
		context.Background(),
		"u1",
		"c1",
		"r",
		0,
		nil,
		nil,
	)
	require.NoError(t, err)

	valResult, err := provider.ValidateRefreshToken(context.Background(), refreshResult.TokenString)
	require.NoError(t, err)
	assert.True(t, valResult.Valid)
	assert.Equal(t, "u1", valResult.UserID)

	// RefreshAccessToken
	refreshed, err := provider.RefreshAccessToken(
		context.Background(),
		refreshResult.TokenString,
		0,
		0,
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.NotNil(t, refreshed.AccessToken)
	assert.NotNil(t, refreshed.RefreshToken, "rotation mode should produce new refresh token")
}

func TestLocalTokenProvider_PublicKey(t *testing.T) {
	rsaKey := getTestRSAKey(t)
	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
		WithKeyID("kid1"),
	)
	require.NoError(t, err)

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
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	assert.Nil(t, provider.PublicKey())
	assert.Empty(t, provider.KeyID())
	assert.Equal(t, "HS256", provider.Algorithm())
}

func TestNewLocalTokenProvider_RS256_NoKey_Error(t *testing.T) {
	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
		// No JWT secret needed for RS256, but no WithSigningKey provided
	}
	_, err := NewLocalTokenProvider(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RS256 requires a signing key")
}

func TestNewLocalTokenProvider_ES256_NoKey_Error(t *testing.T) {
	cfg := &config.Config{
		JWTSigningAlgorithm: "ES256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	_, err := NewLocalTokenProvider(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ES256 requires a signing key")
}

func TestNewLocalTokenProvider_ES256_WrongCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	cfg := &config.Config{
		JWTSigningAlgorithm: "ES256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	_, err = NewLocalTokenProvider(cfg,
		WithSigningKey(key, &key.PublicKey),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires P-256 curve")
}

func TestNewLocalTokenProvider_RS256_WrongKeyType(t *testing.T) {
	ecKey := getTestECKey(t)
	cfg := &config.Config{
		JWTSigningAlgorithm: "RS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	_, err := NewLocalTokenProvider(cfg,
		WithSigningKey(ecKey, &ecKey.PublicKey),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RS256 requires *rsa.PrivateKey")
}

func TestNewLocalTokenProvider_ES256_WrongKeyType(t *testing.T) {
	rsaKey := getTestRSAKey(t)
	cfg := &config.Config{
		JWTSigningAlgorithm: "ES256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	_, err := NewLocalTokenProvider(cfg,
		WithSigningKey(rsaKey, &rsaKey.PublicKey),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ES256 requires *ecdsa.PrivateKey")
}

func TestNewLocalTokenProvider_UnsupportedAlgorithm(t *testing.T) {
	cfg := &config.Config{
		JWTSigningAlgorithm: "PS256",
		JWTExpiration:       1 * time.Hour,
		BaseURL:             "http://localhost:8080",
	}
	_, err := NewLocalTokenProvider(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported JWTSigningAlgorithm")
}

func TestGenerateToken_WithJitter(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:           "test-secret-key-for-jwt-signing",
		JWTExpiration:       1 * time.Hour,
		JWTExpirationJitter: 10 * time.Minute,
		BaseURL:             "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	minExpiry := time.Now().Add(1 * time.Hour)
	maxExpiry := time.Now().Add(1*time.Hour + 10*time.Minute)

	var expirations []time.Time
	for range 20 {
		result, err := provider.GenerateToken(
			context.Background(),
			"user1",
			"client1",
			"read",
			0,
			nil,
			nil,
		)
		require.NoError(t, err)
		assert.True(t, result.ExpiresAt.After(minExpiry) || result.ExpiresAt.Equal(minExpiry),
			"ExpiresAt %v should be >= %v", result.ExpiresAt, minExpiry)
		assert.True(t, result.ExpiresAt.Before(maxExpiry.Add(5*time.Second)),
			"ExpiresAt %v should be < %v", result.ExpiresAt, maxExpiry)
		expirations = append(expirations, result.ExpiresAt)
	}

	// Verify jitter produces variation (not all identical)
	allSame := true
	for _, exp := range expirations[1:] {
		if !exp.Equal(expirations[0]) {
			allSame = false
			break
		}
	}
	assert.False(t, allSame, "jitter should produce varying expiration times")
}

func TestGenerateToken_WithoutJitter(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:           "test-secret-key-for-jwt-signing",
		JWTExpiration:       1 * time.Hour,
		JWTExpirationJitter: 0,
		BaseURL:             "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	result, err := provider.GenerateToken(
		context.Background(),
		"user1",
		"client1",
		"read",
		0,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(1*time.Hour), result.ExpiresAt, 5*time.Second)
}

func TestGenerateRefreshToken_NotAffectedByJitter(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		JWTExpirationJitter:    10 * time.Minute,
		RefreshTokenExpiration: 720 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	result, err := provider.GenerateRefreshToken(
		context.Background(),
		"user1",
		"client1",
		"read",
		0, nil, nil)
	require.NoError(t, err)
	// Refresh token should use RefreshTokenExpiration, not affected by JWTExpirationJitter
	assert.WithinDuration(t, time.Now().Add(720*time.Hour), result.ExpiresAt, 5*time.Second)
}

// ============================================================
// Audience claim — JWT_AUDIENCE config
// ============================================================

func TestGenerateToken_AudienceClaim(t *testing.T) {
	tests := []struct {
		name      string
		audience  []string
		expectAud any // nil means "claim should be absent"
	}{
		{name: "absent when config empty", audience: nil, expectAud: nil},
		{name: "single value collapses to string", audience: []string{"oa"}, expectAud: "oa"},
		{
			name:      "multiple values become array",
			audience:  []string{"oa", "swrd", "hwrd"},
			expectAud: []string{"oa", "swrd", "hwrd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				JWTSecret:     "test-secret-key-for-jwt-signing",
				JWTExpiration: 1 * time.Hour,
				BaseURL:       "http://localhost:8080",
				JWTAudience:   tt.audience,
			}
			provider, err := NewLocalTokenProvider(cfg)
			require.NoError(t, err)

			result, err := provider.GenerateToken(
				context.Background(), "u", "c", "read", 0, nil,
				nil,
			)
			require.NoError(t, err)

			aud, present := result.Claims["aud"]
			if tt.expectAud == nil {
				assert.False(t, present, "aud must be omitted when JWTAudience is empty")
				return
			}
			assert.True(t, present, "aud must be present")
			assert.Equal(t, tt.expectAud, aud)
		})
	}
}

func TestGenerateToken_AudiencePropagatesToValidate(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
		JWTAudience:   []string{"oa"},
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	gen, err := provider.GenerateToken(context.Background(), "u", "c", "read", 0, nil, nil)
	require.NoError(t, err)

	val, err := provider.ValidateToken(context.Background(), gen.TokenString)
	require.NoError(t, err)
	// After round-trip through JSON the aud reads back as a string for single-value
	assert.Equal(t, "oa", val.Claims["aud"])
}

// ============================================================
// Extra claims — project / service_account injection
// ============================================================

func TestGenerateToken_ExtraClaimsInjected(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	// Use prefixed keys directly — the token provider merges whatever the
	// service layer hands it; key composition is the service layer's job.
	extra := map[string]any{
		EmittedName("extra", "project"):         "payments-prod",
		EmittedName("extra", "service_account"): "sa-payments@example.com",
	}
	result, err := provider.GenerateToken(
		context.Background(), "u", "c", "read", 0, extra,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "payments-prod", result.Claims[EmittedName("extra", "project")])
	assert.Equal(
		t,
		"sa-payments@example.com",
		result.Claims[EmittedName("extra", "service_account")],
	)

	val, err := provider.ValidateToken(context.Background(), result.TokenString)
	require.NoError(t, err)
	assert.Equal(t, "payments-prod", val.Claims[EmittedName("extra", "project")])
	assert.Equal(
		t,
		"sa-payments@example.com",
		val.Claims[EmittedName("extra", "service_account")],
	)
}

// Standard claims must not be silently overridden by extraClaims — that would
// allow a misuse to fake the issuer or audience. The contract documented on
// generateJWT is "standard claims always win".
func TestGenerateToken_ExtraClaimsCannotOverrideStandard(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
		JWTAudience:   []string{"oa"},
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	extra := map[string]any{
		"iss":       "https://attacker.example.com",
		"aud":       "wrong-tenant",
		"sub":       "spoofed-user",
		"user_id":   "spoofed-user",
		"client_id": "spoofed-client",
		"scope":     "admin",
		"type":      "refresh",
	}
	result, err := provider.GenerateToken(
		context.Background(), "real-user", "real-client", "read", 0, extra,
		nil,
	)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080", result.Claims["iss"])
	assert.Equal(t, "oa", result.Claims["aud"])
	assert.Equal(t, "real-user", result.Claims["sub"])
	assert.Equal(t, "real-user", result.Claims["user_id"])
	assert.Equal(t, "real-client", result.Claims["client_id"])
	assert.Equal(t, "read", result.Claims["scope"])
	assert.Equal(t, TokenCategoryAccess, result.Claims["type"])
}

// When JWTAudience is unset, an extraClaims map that smuggles in an "aud" must
// not leak into the signed JWT — config is the single source of truth for the
// aud claim. Regression coverage for a bug where extraClaims["aud"] survived
// because the standard-claim write was conditional on JWTAudience being set.
func TestGenerateToken_ExtraClaimsAudIgnoredWhenAudienceUnset(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: 1 * time.Hour,
		BaseURL:       "http://localhost:8080",
		// JWTAudience deliberately left empty
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	extra := map[string]any{"aud": "smuggled-tenant"}
	result, err := provider.GenerateToken(
		context.Background(), "u", "c", "read", 0, extra,
		nil,
	)
	require.NoError(t, err)
	_, present := result.Claims["aud"]
	assert.False(
		t,
		present,
		"aud must be omitted when JWTAudience is empty, even if extraClaims provides one",
	)
}

func TestGenerateRefreshToken_ExtraClaimsInjected(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	extra := map[string]any{EmittedName("extra", "project"): "payments-prod"}
	result, err := provider.GenerateRefreshToken(
		context.Background(), "u", "c", "read", 0, extra,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "payments-prod", result.Claims[EmittedName("extra", "project")])
	assert.Equal(t, TokenCategoryRefresh, result.Claims["type"])
}

func TestGenerateClientCredentialsToken_ExtraClaimsInjected(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:                        "test-secret-key-for-jwt-signing",
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		BaseURL:                          "http://localhost:8080",
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	extra := map[string]any{
		EmittedName("extra", "service_account"): "sa-batch@example.com",
	}
	result, err := provider.GenerateClientCredentialsToken(
		context.Background(), "client:abc", "abc", "read", 0, extra,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(
		t,
		"sa-batch@example.com",
		result.Claims[EmittedName("extra", "service_account")],
	)
}

// RefreshAccessToken must thread the caller-supplied extraClaims into the new
// access token (and the rotated refresh token, if rotation is enabled). This is
// the mechanism that lets project / service_account changes take effect at
// refresh time rather than being frozen at original issuance.
func TestRefreshAccessToken_AppliesExtraClaims(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing",
		JWTExpiration:          1 * time.Hour,
		RefreshTokenExpiration: 30 * 24 * time.Hour,
		BaseURL:                "http://localhost:8080",
		EnableTokenRotation:    true,
	}
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	projectKey := EmittedName("extra", "project")

	// Original refresh token issued with one project value
	original, err := provider.GenerateRefreshToken(
		context.Background(), "u", "c", "read", 0,
		map[string]any{projectKey: "old-project"},
		nil,
	)
	require.NoError(t, err)

	// Refresh, supplying the *current* project value
	refreshed, err := provider.RefreshAccessToken(
		context.Background(),
		original.TokenString,
		0, 0,
		map[string]any{projectKey: "new-project"},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "new-project", refreshed.AccessToken.Claims[projectKey])
	require.NotNil(t, refreshed.RefreshToken, "rotation mode should produce a new refresh token")
	assert.Equal(t, "new-project", refreshed.RefreshToken.Claims[projectKey])
}

// audienceClaim is exercised indirectly via TestGenerateToken_AudienceClaim, but
// the helper has subtle list-copy semantics worth pinning explicitly.
func TestAudienceClaim_HelperShape(t *testing.T) {
	assert.Nil(t, audienceClaim(nil))
	assert.Nil(t, audienceClaim([]string{}))
	assert.Equal(t, "oa", audienceClaim([]string{"oa"}))

	in := []string{"oa", "swrd"}
	out := audienceClaim(in).([]string)
	assert.Equal(t, in, out)
	// Mutating the returned slice must not corrupt the caller's input.
	out[0] = "mutated"
	assert.Equal(t, "oa", in[0], "audienceClaim must defensively copy")
}
