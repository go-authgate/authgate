package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
		JWTExpiration:   1 * time.Hour,
	}

	provider := NewHTTPTokenProvider(cfg)
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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
		JWTExpiration:   1 * time.Hour,
	}

	provider := NewHTTPTokenProvider(cfg)
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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
		JWTExpiration:   1 * time.Hour,
	}

	provider := NewHTTPTokenProvider(cfg)
	_, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPTokenInvalidResp)
	assert.Contains(t, err.Error(), "500")
}

func TestHTTPTokenProvider_GenerateToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("not a valid json"))
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
		JWTExpiration:   1 * time.Hour,
	}

	provider := NewHTTPTokenProvider(cfg)
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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
	}

	provider := NewHTTPTokenProvider(cfg)
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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
	}

	provider := NewHTTPTokenProvider(cfg)
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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
	}

	provider := NewHTTPTokenProvider(cfg)
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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
	}

	provider := NewHTTPTokenProvider(cfg)
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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
	}

	provider := NewHTTPTokenProvider(cfg)
	_, err := provider.ValidateToken(context.Background(), "token")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPTokenInvalidResp)
}

func TestHTTPTokenProvider_Name(t *testing.T) {
	cfg := &config.Config{
		TokenAPIURL:     "http://localhost:9000",
		TokenAPITimeout: 10 * time.Second,
	}
	provider := NewHTTPTokenProvider(cfg)

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

	cfg := &config.Config{
		TokenAPIURL:     server.URL,
		TokenAPITimeout: 10 * time.Second,
		JWTExpiration:   1 * time.Hour,
	}

	provider := NewHTTPTokenProvider(cfg)
	_, err := provider.GenerateToken(context.Background(), "user123", "client456", "read")

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPTokenAuthFailed)
	assert.Contains(t, err.Error(), errorMessage)
}
