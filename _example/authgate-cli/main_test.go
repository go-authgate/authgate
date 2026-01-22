package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func init() {
	// Set default values for tests (don't call initConfig to avoid flag parsing)
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	if clientID == "" {
		clientID = "test-client"
	}
	if tokenFile == "" {
		tokenFile = ".authgate-tokens.json"
	}
	// Initialize httpClient for tests
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
}

func TestSaveTokens_ConcurrentWrites(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile = filepath.Join(tempDir, "tokens.json")

	const goroutines = 10
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			storage := &TokenStorage{
				AccessToken:  fmt.Sprintf("access-token-%d", id),
				RefreshToken: fmt.Sprintf("refresh-token-%d", id),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				ClientID:     fmt.Sprintf("client-%d", id),
			}

			if err := saveTokens(storage); err != nil {
				t.Errorf("Goroutine %d: Failed to save tokens: %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all tokens were saved
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	var storageMap TokenStorageMap
	if err := json.Unmarshal(data, &storageMap); err != nil {
		t.Fatalf("Failed to parse token file: %v", err)
	}

	// Should have all client tokens
	if len(storageMap.Tokens) != goroutines {
		t.Errorf("Expected %d client tokens, got %d", goroutines, len(storageMap.Tokens))
	}

	// Verify each token
	for i := 0; i < goroutines; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		token, ok := storageMap.Tokens[clientID]
		if !ok {
			t.Errorf("Missing token for client %s", clientID)
			continue
		}

		expectedAccessToken := fmt.Sprintf("access-token-%d", i)
		if token.AccessToken != expectedAccessToken {
			t.Errorf(
				"Client %s: Expected access token %s, got %s",
				clientID,
				expectedAccessToken,
				token.AccessToken,
			)
		}
	}

	// Verify no lock files remain
	lockPath := tokenFile + ".lock"
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("Lock file still exists after all saves completed")
	}
}

func TestSaveTokens_PreservesOtherClients(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile = filepath.Join(tempDir, "tokens.json")

	// Save first client
	clientID = "client-1"
	storage1 := &TokenStorage{
		AccessToken:  "token-1",
		RefreshToken: "refresh-1",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		ClientID:     "client-1",
	}
	if err := saveTokens(storage1); err != nil {
		t.Fatalf("Failed to save first client: %v", err)
	}

	// Save second client (should preserve first)
	clientID = "client-2"
	storage2 := &TokenStorage{
		AccessToken:  "token-2",
		RefreshToken: "refresh-2",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		ClientID:     "client-2",
	}
	if err := saveTokens(storage2); err != nil {
		t.Fatalf("Failed to save second client: %v", err)
	}

	// Load and verify both exist
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	var storageMap TokenStorageMap
	if err := json.Unmarshal(data, &storageMap); err != nil {
		t.Fatalf("Failed to parse token file: %v", err)
	}

	if len(storageMap.Tokens) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(storageMap.Tokens))
	}

	if token, ok := storageMap.Tokens["client-1"]; !ok || token.AccessToken != "token-1" {
		t.Errorf("Client 1 token was not preserved")
	}

	if token, ok := storageMap.Tokens["client-2"]; !ok || token.AccessToken != "token-2" {
		t.Errorf("Client 2 token was not saved correctly")
	}
}

func BenchmarkSaveTokens_SingleClient(b *testing.B) {
	tempDir := b.TempDir()
	tokenFile = filepath.Join(tempDir, "tokens.json")
	clientID = "bench-client"

	storage := &TokenStorage{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		ClientID:     clientID,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := saveTokens(storage); err != nil {
			b.Fatalf("Failed to save tokens: %v", err)
		}
	}
}

func BenchmarkSaveTokens_ParallelWrites(b *testing.B) {
	tempDir := b.TempDir()
	tokenFile = filepath.Join(tempDir, "tokens.json")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		id := 0
		for pb.Next() {
			storage := &TokenStorage{
				AccessToken:  fmt.Sprintf("access-token-%d", id),
				RefreshToken: fmt.Sprintf("refresh-token-%d", id),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				ClientID:     fmt.Sprintf("client-%d", id),
			}

			if err := saveTokens(storage); err != nil {
				b.Fatalf("Failed to save tokens: %v", err)
			}
			id++
		}
	})
}

func TestValidateTokenResponse(t *testing.T) {
	tests := []struct {
		name        string
		accessToken string
		tokenType   string
		expiresIn   int
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid token response",
			accessToken: "valid-access-token-123456",
			tokenType:   "Bearer",
			expiresIn:   3600,
			wantErr:     false,
		},
		{
			name:        "valid token with empty type (optional field)",
			accessToken: "valid-access-token-123456",
			tokenType:   "",
			expiresIn:   3600,
			wantErr:     false,
		},
		{
			name:        "empty access token",
			accessToken: "",
			tokenType:   "Bearer",
			expiresIn:   3600,
			wantErr:     true,
			errContains: "access_token is empty",
		},
		{
			name:        "access token too short",
			accessToken: "short",
			tokenType:   "Bearer",
			expiresIn:   3600,
			wantErr:     true,
			errContains: "access_token is too short",
		},
		{
			name:        "zero expires_in",
			accessToken: "valid-access-token-123456",
			tokenType:   "Bearer",
			expiresIn:   0,
			wantErr:     true,
			errContains: "expires_in must be positive",
		},
		{
			name:        "negative expires_in",
			accessToken: "valid-access-token-123456",
			tokenType:   "Bearer",
			expiresIn:   -3600,
			wantErr:     true,
			errContains: "expires_in must be positive",
		},
		{
			name:        "invalid token type",
			accessToken: "valid-access-token-123456",
			tokenType:   "Basic",
			expiresIn:   3600,
			wantErr:     true,
			errContains: "unexpected token_type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenResponse(tt.accessToken, tt.tokenType, tt.expiresIn)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateTokenResponse() expected error but got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf(
						"validateTokenResponse() error = %v, want error containing %q",
						err,
						tt.errContains,
					)
				}
			} else {
				if err != nil {
					t.Errorf("validateTokenResponse() unexpected error = %v", err)
				}
			}
		})
	}
}

// contains checks if string s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRefreshAccessToken_RotationMode(t *testing.T) {
	// Save original values
	origServerURL := serverURL
	origClientID := clientID
	origTokenFile := tokenFile

	// Restore after test
	defer func() {
		serverURL = origServerURL
		clientID = origClientID
		tokenFile = origTokenFile
	}()

	tempDir := t.TempDir()
	tokenFile = filepath.Join(tempDir, "tokens.json")
	clientID = "test-client-rotation"

	tests := []struct {
		name                 string
		oldRefreshToken      string
		responseRefreshToken string // Empty string means server doesn't return refresh_token
		expectedRefreshToken string
		description          string
	}{
		{
			name:                 "rotation mode - server returns new refresh token",
			oldRefreshToken:      "old-refresh-token",
			responseRefreshToken: "new-refresh-token",
			expectedRefreshToken: "new-refresh-token",
			description:          "Should use new refresh token from server",
		},
		{
			name:                 "fixed mode - server doesn't return refresh token",
			oldRefreshToken:      "old-refresh-token",
			responseRefreshToken: "",
			expectedRefreshToken: "old-refresh-token",
			description:          "Should preserve old refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/token" {
					http.NotFound(w, r)
					return
				}

				// Parse form to verify grant_type
				if err := r.ParseForm(); err != nil {
					http.Error(w, "Invalid form", http.StatusBadRequest)
					return
				}

				grantType := r.FormValue("grant_type")
				if grantType != "refresh_token" {
					http.Error(w, "Invalid grant_type", http.StatusBadRequest)
					return
				}

				// Build response
				response := map[string]interface{}{
					"access_token": "new-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}

				// Only include refresh_token if not empty (simulates rotation vs fixed mode)
				if tt.responseRefreshToken != "" {
					response["refresh_token"] = tt.responseRefreshToken
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			// Update serverURL to point to mock server
			serverURL = server.URL

			// Call refreshAccessToken
			storage, err := refreshAccessToken(tt.oldRefreshToken)
			if err != nil {
				t.Fatalf("refreshAccessToken() error = %v", err)
			}

			// Verify access token
			if storage.AccessToken != "new-access-token" {
				t.Errorf(
					"AccessToken = %v, want %v",
					storage.AccessToken,
					"new-access-token",
				)
			}

			// Verify refresh token (this is the key test)
			if storage.RefreshToken != tt.expectedRefreshToken {
				t.Errorf(
					"%s: RefreshToken = %v, want %v",
					tt.description,
					storage.RefreshToken,
					tt.expectedRefreshToken,
				)
			}

			// Verify token was saved to file
			data, err := os.ReadFile(tokenFile)
			if err != nil {
				t.Fatalf("Failed to read token file: %v", err)
			}

			var storageMap TokenStorageMap
			if err := json.Unmarshal(data, &storageMap); err != nil {
				t.Fatalf("Failed to parse token file: %v", err)
			}

			savedToken, ok := storageMap.Tokens[clientID]
			if !ok {
				t.Fatalf("Token not found in file for client %s", clientID)
			}

			if savedToken.RefreshToken != tt.expectedRefreshToken {
				t.Errorf(
					"Saved RefreshToken = %v, want %v",
					savedToken.RefreshToken,
					tt.expectedRefreshToken,
				)
			}
		})
	}
}

func TestRefreshAccessToken_ValidationErrors(t *testing.T) {
	// Save original values
	origServerURL := serverURL
	origClientID := clientID
	origTokenFile := tokenFile

	// Restore after test
	defer func() {
		serverURL = origServerURL
		clientID = origClientID
		tokenFile = origTokenFile
	}()

	tempDir := t.TempDir()
	tokenFile = filepath.Join(tempDir, "tokens.json")
	clientID = "test-client-validation"

	tests := []struct {
		name         string
		responseBody map[string]interface{}
		wantErr      bool
		errContains  string
	}{
		{
			name: "invalid - empty access token",
			responseBody: map[string]interface{}{
				"access_token": "",
				"token_type":   "Bearer",
				"expires_in":   3600,
			},
			wantErr:     true,
			errContains: "access_token is empty",
		},
		{
			name: "invalid - access token too short",
			responseBody: map[string]interface{}{
				"access_token": "short",
				"token_type":   "Bearer",
				"expires_in":   3600,
			},
			wantErr:     true,
			errContains: "access_token is too short",
		},
		{
			name: "invalid - zero expires_in",
			responseBody: map[string]interface{}{
				"access_token": "valid-token-123456",
				"token_type":   "Bearer",
				"expires_in":   0,
			},
			wantErr:     true,
			errContains: "expires_in must be positive",
		},
		{
			name: "invalid - wrong token type",
			responseBody: map[string]interface{}{
				"access_token": "valid-token-123456",
				"token_type":   "Basic",
				"expires_in":   3600,
			},
			wantErr:     true,
			errContains: "unexpected token_type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			// Update serverURL to point to mock server
			serverURL = server.URL

			// Call refreshAccessToken
			_, err := refreshAccessToken("test-refresh-token")

			if tt.wantErr {
				if err == nil {
					t.Errorf("refreshAccessToken() expected error but got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf(
						"refreshAccessToken() error = %v, want error containing %q",
						err,
						tt.errContains,
					)
				}
			} else {
				if err != nil {
					t.Errorf("refreshAccessToken() unexpected error = %v", err)
				}
			}
		})
	}
}
