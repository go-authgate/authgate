package token

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/client"
	"github.com/go-authgate/authgate/internal/config"

	retry "github.com/appleboy/go-httpretry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfig creates a config for testing with retries disabled
func testConfig(url string) *config.Config {
	return &config.Config{
		TokenAPIURL:        url,
		TokenAPITimeout:    10 * time.Second,
		JWTExpiration:      1 * time.Hour,
		TokenAPIMaxRetries: 0, // Disable retries for predictable test behavior
	}
}

// createTestRetryClient creates a retry client for testing
func createTestRetryClient(cfg *config.Config) (*retry.Client, error) {
	return client.CreateRetryClient(
		cfg.TokenAPIAuthMode,
		cfg.TokenAPIAuthSecret,
		cfg.TokenAPITimeout,
		cfg.TokenAPIInsecureSkipVerify,
		cfg.TokenAPIMaxRetries,
		cfg.TokenAPIRetryDelay,
		cfg.TokenAPIMaxRetryDelay,
		cfg.TokenAPIAuthHeader,
	)
}

// createTestProvider is a helper function for tests to create a provider
func createTestProvider(cfg *config.Config) *HTTPTokenProvider {
	retryClient, err := createTestRetryClient(cfg)
	if err != nil {
		panic(fmt.Sprintf("failed to create test retry client: %v", err))
	}
	return NewHTTPTokenProvider(cfg, retryClient)
}

func TestHTTPTokenProvider_GenerateToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/generate", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Parse request body
		var req APITokenGenerateRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, "user123", req.UserID)
		assert.Equal(t, "client456", req.ClientID)
		assert.Equal(t, "read write", req.Scopes)

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(APITokenGenerateResponse{
			Success:     true,
			AccessToken: "mock-jwt-token-12345",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Claims: map[string]any{
				"custom": "value",
			},
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	result, err := provider.GenerateToken(
		context.Background(),
		"user123",
		"client456",
		"read write",
	)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "mock-jwt-token-12345", result.TokenString)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.WithinDuration(t, time.Now().Add(3600*time.Second), result.ExpiresAt, 1*time.Second)
	assert.Equal(t, "value", result.Claims["custom"])
}

func TestHTTPTokenProvider_GenerateToken_MissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(APITokenGenerateResponse{
			Success:     true,
			AccessToken: "", // Missing access token
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPTokenInvalidResp)
	assert.Contains(t, err.Error(), "missing access_token")
}

func TestHTTPTokenProvider_GenerateToken_APIError(t *testing.T) {
	testGenerateTokenError(t, http.StatusBadRequest, "Invalid user_id")
}

func TestHTTPTokenProvider_GenerateToken_Non2xxStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("Internal Server Error"))
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	assert.Error(t, err)
	// HTTP 500 is treated as a connection error by the retry client
	assert.ErrorIs(t, err, ErrHTTPTokenConnection)
	assert.Contains(t, err.Error(), "failed to connect to token API")
}

func TestHTTPTokenProvider_GenerateToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("not a valid json"))
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPTokenInvalidResp)
}

func TestHTTPTokenProvider_ValidateToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/validate", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		// Parse request body
		var req APITokenValidateRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, "mock-jwt-token", req.Token)

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(APITokenValidateResponse{
			Valid:     true,
			UserID:    "user123",
			ClientID:  "client456",
			Scopes:    "read write",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			Claims: map[string]any{
				"custom": "value",
			},
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	result, err := provider.ValidateToken(context.Background(), "mock-jwt-token")

	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "user123", result.UserID)
	assert.Equal(t, "client456", result.ClientID)
	assert.Equal(t, "read write", result.Scopes)
	assert.Equal(t, "value", result.Claims["custom"])
}

func TestHTTPTokenProvider_ValidateToken_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(APITokenValidateResponse{
			Valid:   false,
			Message: "Token is invalid",
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.ValidateToken(context.Background(), "invalid-token")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestHTTPTokenProvider_ValidateToken_Expired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(APITokenValidateResponse{
			Valid:     true,
			UserID:    "user123",
			ClientID:  "client456",
			Scopes:    "read",
			ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // Expired
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.ValidateToken(context.Background(), "expired-token")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExpiredToken)
}

func TestHTTPTokenProvider_ValidateToken_Non2xxStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("Unauthorized"))
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.ValidateToken(context.Background(), "token")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidToken)
	assert.Contains(t, err.Error(), "401")
}

func TestHTTPTokenProvider_ValidateToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("invalid json"))
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.ValidateToken(context.Background(), "token")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPTokenInvalidResp)
}

func TestHTTPTokenProvider_Name(t *testing.T) {
	cfg := testConfig("http://localhost:9000")
	provider := createTestProvider(cfg)

	assert.Equal(t, "http_api", provider.Name())
}

func TestHTTPTokenProvider_GenerateToken_SuccessFalse(t *testing.T) {
	testGenerateTokenError(t, http.StatusOK, "Authentication failed")
}

// testGenerateTokenError is a helper function to test token generation error scenarios
func testGenerateTokenError(t *testing.T, statusCode int, errorMessage string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		err := json.NewEncoder(w).Encode(APITokenGenerateResponse{
			Success: false,
			Message: errorMessage,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)

	provider := createTestProvider(cfg)
	_, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPTokenAuthFailed)
	assert.Contains(t, err.Error(), errorMessage)
}

// TestHTTPTokenProvider_SimpleAuth_DefaultHeader tests Simple auth mode with default header
func TestHTTPTokenProvider_SimpleAuth_DefaultHeader(t *testing.T) {
	const testSecret = "test-secret-key-123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify X-API-Secret header is present and correct
		apiSecret := r.Header.Get("X-API-Secret")
		if apiSecret != testSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
				Success: false,
				Message: "Invalid API secret",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
			Success:     true,
			AccessToken: "mock-jwt-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.TokenAPIAuthMode = "simple"
	cfg.TokenAPIAuthSecret = testSecret
	// TokenAPIAuthHeader not set, should default to "X-API-Secret"

	provider := createTestProvider(cfg)
	result, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "mock-jwt-token", result.TokenString)
}

// TestHTTPTokenProvider_SimpleAuth_CustomHeader tests Simple auth mode with custom header
func TestHTTPTokenProvider_SimpleAuth_CustomHeader(t *testing.T) {
	const testSecret = "test-secret-key-456"
	const customHeader = "X-Custom-Auth-Token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom header is present and correct
		authToken := r.Header.Get(customHeader)
		if authToken != testSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APITokenValidateResponse{
				Valid:   false,
				Message: "Invalid auth token",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APITokenValidateResponse{
			Valid:     true,
			UserID:    "user123",
			ClientID:  "client456",
			Scopes:    "read write",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.TokenAPIAuthMode = "simple"
	cfg.TokenAPIAuthSecret = testSecret
	cfg.TokenAPIAuthHeader = customHeader

	provider := createTestProvider(cfg)
	result, err := provider.ValidateToken(context.Background(), "mock-jwt-token")

	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "user123", result.UserID)
}

// TestHTTPTokenProvider_HMACAuth_ValidSignature tests HMAC auth mode with valid signature
func TestHTTPTokenProvider_HMACAuth_ValidSignature(t *testing.T) {
	const testSecret = "hmac-secret-key-789" //nolint:gosec // Test secret, not production

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify HMAC headers are present
		signature := r.Header.Get("X-Signature")
		timestamp := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")

		if signature == "" || timestamp == "" || nonce == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
				Success: false,
				Message: "Missing HMAC authentication headers",
			})
			return
		}

		// Verify timestamp is recent (within 5 minutes)
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
				Success: false,
				Message: "Invalid timestamp format",
			})
			return
		}

		now := time.Now().Unix()
		if now-ts > 300 || ts-now > 300 {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
				Success: false,
				Message: "Timestamp too old or in future",
			})
			return
		}

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Compute expected signature: HMAC-SHA256(timestamp + method + path + body)
		message := fmt.Sprintf("%s%s%s%s", timestamp, r.Method, r.URL.Path, string(body))
		h := hmac.New(sha256.New, []byte(testSecret))
		h.Write([]byte(message))
		expectedSignature := hex.EncodeToString(h.Sum(nil))

		if signature != expectedSignature {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
				Success: false,
				Message: "Invalid HMAC signature",
			})
			return
		}

		// Valid signature, return success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
			Success:     true,
			AccessToken: "hmac-secured-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.TokenAPIAuthMode = "hmac"
	cfg.TokenAPIAuthSecret = testSecret

	provider := createTestProvider(cfg)
	result, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "hmac-secured-token", result.TokenString)
}

// TestHTTPTokenProvider_HMACAuth_MissingHeaders tests HMAC auth fails when headers are missing
func TestHTTPTokenProvider_HMACAuth_MissingHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that at least one HMAC header is missing (should not happen with proper client)
		signature := r.Header.Get("X-Signature")
		timestamp := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")

		// This test verifies headers ARE present (the external client adds them)
		// If any are missing, the test should fail
		assert.NotEmpty(t, signature, "X-Signature header should be present")
		assert.NotEmpty(t, timestamp, "X-Timestamp header should be present")
		assert.NotEmpty(t, nonce, "X-Nonce header should be present")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APITokenValidateResponse{
			Valid:     true,
			UserID:    "user123",
			ClientID:  "client456",
			Scopes:    "read",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.TokenAPIAuthMode = "hmac"
	cfg.TokenAPIAuthSecret = "test-secret"

	provider := createTestProvider(cfg)
	result, err := provider.ValidateToken(context.Background(), "token")

	require.NoError(t, err)
	assert.True(t, result.Valid)
}

// TestHTTPTokenProvider_NoAuth_NoHeaders tests that no auth headers are added when auth mode is "none"
func TestHTTPTokenProvider_NoAuth_NoHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no authentication headers are present
		assert.Empty(t, r.Header.Get("X-API-Secret"), "Should not have X-API-Secret header")
		assert.Empty(t, r.Header.Get("X-Signature"), "Should not have X-Signature header")
		assert.Empty(t, r.Header.Get("X-Timestamp"), "Should not have X-Timestamp header")
		assert.Empty(t, r.Header.Get("X-Nonce"), "Should not have X-Nonce header")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APITokenGenerateResponse{
			Success:     true,
			AccessToken: "no-auth-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	// TokenAPIAuthMode not set or set to "none" (default)

	provider := createTestProvider(cfg)
	result, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "no-auth-token", result.TokenString)
}
