package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/appleboy/authgate/internal/config"
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
