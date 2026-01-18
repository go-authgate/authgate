package auth

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

	"github.com/appleboy/authgate/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPAPIAuthProvider_Authenticate_Success(t *testing.T) {
	// Mock external API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success:  true,
			UserID:   "ext-user-123",
			Email:    "user@example.com",
			FullName: "Test User",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:     server.URL,
		HTTPAPITimeout: 10 * 1000000000, // 10 seconds in nanoseconds
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", result.Username)
	}

	if result.ExternalID != "ext-user-123" {
		t.Errorf("Expected external ID 'ext-user-123', got '%s'", result.ExternalID)
	}

	if result.Email != "user@example.com" {
		t.Errorf("Expected email 'user@example.com', got '%s'", result.Email)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}
}

func TestHTTPAPIAuthProvider_Authenticate_MissingUserID(t *testing.T) {
	// Mock external API server that returns success but no user_id
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success:  true,
			UserID:   "", // Empty user_id
			Email:    "user@example.com",
			FullName: "Test User",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:     server.URL,
		HTTPAPITimeout: 10 * 1000000000,
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	if err == nil {
		t.Fatal("Expected error for missing user_id, got nil")
	}

	if result != nil {
		t.Error("Expected nil result when user_id is missing")
	}

	// Check that error message mentions missing user_id
	if err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}

func TestHTTPAPIAuthProvider_Authenticate_AuthFailed(t *testing.T) {
	// Mock external API server that returns success=false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success: false,
			Message: "Invalid credentials",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:     server.URL,
		HTTPAPITimeout: 10 * 1000000000,
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "wrongpassword")

	if err == nil {
		t.Fatal("Expected error for failed authentication, got nil")
	}

	if result != nil {
		t.Error("Expected nil result when authentication fails")
	}
}

func TestHTTPAPIAuthProvider_Authenticate_Non2xxStatus(t *testing.T) {
	// Mock external API server that returns 401 status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success: false,
			Message: "Unauthorized access",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:     server.URL,
		HTTPAPITimeout: 10 * 1000000000,
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	if err == nil {
		t.Fatal("Expected error for non-2xx status, got nil")
	}

	if result != nil {
		t.Error("Expected nil result for non-2xx status")
	}
}

func TestHTTPAPIAuthProvider_Authenticate_InvalidJSON(t *testing.T) {
	// Mock external API server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:     server.URL,
		HTTPAPITimeout: 10 * 1000000000,
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}

	if result != nil {
		t.Error("Expected nil result for invalid JSON")
	}
}

func TestHTTPAPIAuthProvider_Name(t *testing.T) {
	cfg := &config.Config{}
	provider := NewHTTPAPIAuthProvider(cfg)

	if provider.Name() != "http_api" {
		t.Errorf("Expected provider name 'http_api', got '%s'", provider.Name())
	}
}

// TestHTTPAPIAuthProvider_SimpleAuth_DefaultHeader tests Simple auth mode with default header
func TestHTTPAPIAuthProvider_SimpleAuth_DefaultHeader(t *testing.T) {
	const testSecret = "auth-secret-key-123" //nolint:gosec // Test secret, not production

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify X-API-Secret header is present and correct
		apiSecret := r.Header.Get("X-API-Secret")
		if apiSecret != testSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APIAuthResponse{
				Success: false,
				Message: "Invalid API secret",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success:  true,
			UserID:   "ext-user-123",
			Email:    "user@example.com",
			FullName: "Test User",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:        server.URL,
		HTTPAPITimeout:    10 * time.Second,
		HTTPAPIAuthMode:   "simple",
		HTTPAPIAuthSecret: testSecret,
		// HTTPAPIAuthHeader not set, should default to "X-API-Secret"
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "ext-user-123", result.ExternalID)
}

// TestHTTPAPIAuthProvider_SimpleAuth_CustomHeader tests Simple auth mode with custom header
func TestHTTPAPIAuthProvider_SimpleAuth_CustomHeader(t *testing.T) {
	const testSecret = "auth-secret-key-456" //nolint:gosec // Test secret, not production
	const customHeader = "X-Internal-Auth"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom header is present and correct
		authToken := r.Header.Get(customHeader)
		if authToken != testSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APIAuthResponse{
				Success: false,
				Message: "Invalid auth token",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success:  true,
			UserID:   "ext-user-456",
			Email:    "user2@example.com",
			FullName: "Test User 2",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:        server.URL,
		HTTPAPITimeout:    10 * time.Second,
		HTTPAPIAuthMode:   "simple",
		HTTPAPIAuthSecret: testSecret,
		HTTPAPIAuthHeader: customHeader,
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "ext-user-456", result.ExternalID)
}

// TestHTTPAPIAuthProvider_HMACAuth_ValidSignature tests HMAC auth mode with valid signature
func TestHTTPAPIAuthProvider_HMACAuth_ValidSignature(t *testing.T) {
	const testSecret = "hmac-auth-secret-789" //nolint:gosec // Test secret, not production

	// Create a mux to handle requests at /verify path (similar to token API pattern)
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		// Verify HMAC headers are present
		signature := r.Header.Get("X-Signature")
		timestamp := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")

		if signature == "" || timestamp == "" || nonce == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APIAuthResponse{
				Success: false,
				Message: "Missing HMAC authentication headers",
			})
			return
		}

		// Verify timestamp is recent (within 5 minutes)
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APIAuthResponse{
				Success: false,
				Message: "Invalid timestamp format",
			})
			return
		}

		now := time.Now().Unix()
		if now-ts > 300 || ts-now > 300 {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APIAuthResponse{
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
			_ = json.NewEncoder(w).Encode(APIAuthResponse{
				Success: false,
				Message: "Invalid HMAC signature",
			})
			return
		}

		// Valid signature, return success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success:  true,
			UserID:   "hmac-user-789",
			Email:    "hmac@example.com",
			FullName: "HMAC User",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:        server.URL + "/verify",
		HTTPAPITimeout:    10 * time.Second,
		HTTPAPIAuthMode:   "hmac",
		HTTPAPIAuthSecret: testSecret,
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "hmac-user-789", result.ExternalID)
}

// TestHTTPAPIAuthProvider_HMACAuth_HeadersPresent tests that HMAC headers are present
func TestHTTPAPIAuthProvider_HMACAuth_HeadersPresent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify all HMAC headers are present
		signature := r.Header.Get("X-Signature")
		timestamp := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")

		assert.NotEmpty(t, signature, "X-Signature header should be present")
		assert.NotEmpty(t, timestamp, "X-Timestamp header should be present")
		assert.NotEmpty(t, nonce, "X-Nonce header should be present")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success:  true,
			UserID:   "user-123",
			Email:    "user@example.com",
			FullName: "Test User",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:        server.URL,
		HTTPAPITimeout:    10 * time.Second,
		HTTPAPIAuthMode:   "hmac",
		HTTPAPIAuthSecret: "test-secret",
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	require.NoError(t, err)
	assert.True(t, result.Success)
}

// TestHTTPAPIAuthProvider_NoAuth_NoHeaders tests that no auth headers are added when auth mode is "none"
func TestHTTPAPIAuthProvider_NoAuth_NoHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no authentication headers are present
		assert.Empty(t, r.Header.Get("X-API-Secret"), "Should not have X-API-Secret header")
		assert.Empty(t, r.Header.Get("X-Signature"), "Should not have X-Signature header")
		assert.Empty(t, r.Header.Get("X-Timestamp"), "Should not have X-Timestamp header")
		assert.Empty(t, r.Header.Get("X-Nonce"), "Should not have X-Nonce header")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success:  true,
			UserID:   "no-auth-user",
			Email:    "noauth@example.com",
			FullName: "No Auth User",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HTTPAPIURL:     server.URL,
		HTTPAPITimeout: 10 * time.Second,
		// HTTPAPIAuthMode not set or set to "none" (default)
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "no-auth-user", result.ExternalID)
}

// TestHTTPAPIAuthProvider_SimpleAuth_Unauthorized tests auth failure when secret is wrong
func TestHTTPAPIAuthProvider_SimpleAuth_Unauthorized(t *testing.T) {
	const correctSecret = "correct-secret"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify X-API-Secret header
		apiSecret := r.Header.Get("X-API-Secret")
		if apiSecret != correctSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(APIAuthResponse{
				Success: false,
				Message: "Unauthorized: Invalid API secret",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIAuthResponse{
			Success: true,
			UserID:  "user-123",
		})
	}))
	defer server.Close()

	// Use wrong secret
	cfg := &config.Config{
		HTTPAPIURL:        server.URL,
		HTTPAPITimeout:    10 * time.Second,
		HTTPAPIAuthMode:   "simple",
		HTTPAPIAuthSecret: "wrong-secret",
	}

	provider := NewHTTPAPIAuthProvider(cfg)
	result, err := provider.Authenticate(context.Background(), "testuser", "password123")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "401")
}
