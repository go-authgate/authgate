package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	retry "github.com/appleboy/go-httpretry"
)

func init() {
	// Initialize globals for tests without calling initConfig (avoids flag conflicts).
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	if clientID == "" {
		clientID = "test-client"
	}
	if tokenFile == "" {
		tokenFile = ".authgate-tokens.json"
	}
	if scope == "" {
		scope = "read write"
	}
	if retryClient == nil {
		var err error
		retryClient, err = retry.NewClient()
		if err != nil {
			panic(fmt.Sprintf("failed to create retry client: %v", err))
		}
	}
}

// -----------------------------------------------------------------------
// Config helpers
// -----------------------------------------------------------------------

func TestValidateServerURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid http", "http://localhost:8080", false},
		{"valid https", "https://auth.example.com", false},
		{"empty", "", true},
		{"no scheme", "localhost:8080", true},
		{"bad scheme", "ftp://example.com", true},
		{"no host", "http://", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServerURL(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateServerURL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestGetConfig_Priority(t *testing.T) {
	t.Setenv("MYKEY", "from-env")

	if got := getConfig("from-flag", "MYKEY", "default"); got != "from-flag" {
		t.Errorf("expected flag value, got %q", got)
	}
	if got := getConfig("", "MYKEY", "default"); got != "from-env" {
		t.Errorf("expected env value, got %q", got)
	}

	t.Setenv("MYKEY", "")
	if got := getConfig("", "MYKEY", "default"); got != "default" {
		t.Errorf("expected default, got %q", got)
	}
}

func TestIsPublicClient(t *testing.T) {
	orig := clientSecret
	t.Cleanup(func() { clientSecret = orig })

	clientSecret = ""
	if !isPublicClient() {
		t.Error("expected public client when secret is empty")
	}
	clientSecret = "secret"
	if isPublicClient() {
		t.Error("expected confidential client when secret is set")
	}
}

// -----------------------------------------------------------------------
// Token response validation
// -----------------------------------------------------------------------

func TestValidateTokenResponse(t *testing.T) {
	tests := []struct {
		name        string
		accessToken string
		tokenType   string
		expiresIn   int
		wantErr     bool
	}{
		{"valid bearer", "a-long-enough-token", "Bearer", 3600, false},
		{"valid empty type", "a-long-enough-token", "", 3600, false},
		{"empty access token", "", "Bearer", 3600, true},
		{"too short token", "short", "Bearer", 3600, true},
		{"zero expires_in", "a-long-enough-token", "Bearer", 0, true},
		{"negative expires_in", "a-long-enough-token", "Bearer", -1, true},
		{"wrong token type", "a-long-enough-token", "MAC", 3600, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenResponse(tc.accessToken, tc.tokenType, tc.expiresIn)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTokenResponse() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Token storage
// -----------------------------------------------------------------------

func TestSaveAndLoadTokens(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "tokens-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	origTokenFile := tokenFile
	origClientID := clientID
	t.Cleanup(func() {
		tokenFile = origTokenFile
		clientID = origClientID
	})

	tokenFile = tmpFile.Name()
	clientID = "test-client-id"

	storage := &TokenStorage{
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		ClientID:     clientID,
		Flow:         "browser",
	}

	if err := saveTokens(storage); err != nil {
		t.Fatalf("saveTokens() error: %v", err)
	}

	loaded, err := loadTokens()
	if err != nil {
		t.Fatalf("loadTokens() error: %v", err)
	}

	if loaded.AccessToken != storage.AccessToken {
		t.Errorf("AccessToken mismatch: got %q, want %q", loaded.AccessToken, storage.AccessToken)
	}
	if loaded.Flow != storage.Flow {
		t.Errorf("Flow mismatch: got %q, want %q", loaded.Flow, storage.Flow)
	}
}

func TestSaveTokens_MultipleClients(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "tokens-multi-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	origTokenFile := tokenFile
	origClientID := clientID
	t.Cleanup(func() {
		tokenFile = origTokenFile
		clientID = origClientID
	})

	tokenFile = tmpFile.Name()

	for _, id := range []string{"client-a", "client-b"} {
		clientID = id
		if err := saveTokens(&TokenStorage{
			AccessToken:  "token-" + id,
			RefreshToken: "refresh-" + id,
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
			ClientID:     id,
		}); err != nil {
			t.Fatalf("saveTokens(%s) error: %v", id, err)
		}
	}

	data, _ := os.ReadFile(tokenFile)
	var sm TokenStorageMap
	if err := json.Unmarshal(data, &sm); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(sm.Tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(sm.Tokens))
	}
}

func TestSaveTokens_ConcurrentWrites(t *testing.T) {
	tempDir := t.TempDir()
	origTokenFile := tokenFile
	t.Cleanup(func() { tokenFile = origTokenFile })
	tokenFile = filepath.Join(tempDir, "tokens.json")

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			if err := saveTokens(&TokenStorage{
				AccessToken:  fmt.Sprintf("access-token-%d", id),
				RefreshToken: fmt.Sprintf("refresh-token-%d", id),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(time.Hour),
				ClientID:     fmt.Sprintf("client-%d", id),
			}); err != nil {
				t.Errorf("goroutine %d: saveTokens() error: %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}
	var sm TokenStorageMap
	if err := json.Unmarshal(data, &sm); err != nil {
		t.Fatalf("failed to parse token file: %v", err)
	}
	if len(sm.Tokens) != goroutines {
		t.Errorf("expected %d tokens, got %d", goroutines, len(sm.Tokens))
	}
}

// -----------------------------------------------------------------------
// Authorization URL construction
// -----------------------------------------------------------------------

func TestBuildAuthURL_ContainsRequiredParams(t *testing.T) {
	origServerURL := serverURL
	origClientID := clientID
	origRedirectURI := redirectURI
	origScope := scope
	t.Cleanup(func() {
		serverURL = origServerURL
		clientID = origClientID
		redirectURI = origRedirectURI
		scope = origScope
	})

	serverURL = "http://localhost:8080"
	clientID = "my-client-id"
	redirectURI = "http://localhost:8888/callback"
	scope = "read write"

	pkce := &PKCEParams{
		Verifier:  "test-verifier",
		Challenge: "test-challenge",
		Method:    "S256",
	}
	state := "random-state"

	u := buildAuthURL(state, pkce)

	for _, want := range []string{
		"client_id=my-client-id",
		"redirect_uri=",
		"response_type=code",
		"scope=",
		"state=random-state",
		"code_challenge=test-challenge",
		"code_challenge_method=S256",
	} {
		if !containsSubstring(u, want) {
			t.Errorf("auth URL missing %q\nURL: %s", want, u)
		}
	}
}

// -----------------------------------------------------------------------
// Refresh token: rotation vs fixed mode
// -----------------------------------------------------------------------

func TestRefreshAccessToken_RotationMode(t *testing.T) {
	origServerURL := serverURL
	origClientID := clientID
	origTokenFile := tokenFile
	t.Cleanup(func() {
		serverURL = origServerURL
		clientID = origClientID
		tokenFile = origTokenFile
	})

	tempDir := t.TempDir()
	tokenFile = filepath.Join(tempDir, "tokens.json")
	clientID = "test-client-rotation"

	tests := []struct {
		name                 string
		oldRefreshToken      string
		responseRefreshToken string
		expectedRefreshToken string
	}{
		{
			name:                 "rotation mode - server returns new refresh token",
			oldRefreshToken:      "old-refresh-token",
			responseRefreshToken: "new-refresh-token",
			expectedRefreshToken: "new-refresh-token",
		},
		{
			name:                 "fixed mode - server doesn't return refresh token",
			oldRefreshToken:      "old-refresh-token",
			responseRefreshToken: "",
			expectedRefreshToken: "old-refresh-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := r.ParseForm(); err != nil {
						http.Error(w, "bad form", http.StatusBadRequest)
						return
					}
					resp := map[string]interface{}{
						"access_token": "new-access-token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					}
					if tt.responseRefreshToken != "" {
						resp["refresh_token"] = tt.responseRefreshToken
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
				}),
			)
			defer srv.Close()

			serverURL = srv.URL

			storage, err := refreshAccessToken(tt.oldRefreshToken)
			if err != nil {
				t.Fatalf("refreshAccessToken() error: %v", err)
			}
			if storage.RefreshToken != tt.expectedRefreshToken {
				t.Errorf(
					"RefreshToken = %q, want %q",
					storage.RefreshToken,
					tt.expectedRefreshToken,
				)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Device code request with retry
// -----------------------------------------------------------------------

func TestRequestDeviceCode_WithRetry(t *testing.T) {
	origServerURL := serverURL
	origClientID := clientID
	t.Cleanup(func() {
		serverURL = origServerURL
		clientID = origClientID
	})

	clientID = "test-client"

	var attemptCount atomic.Int32
	var testServer *httptest.Server

	testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attemptCount.Add(1)
		if count < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "test-device-code",
			"user_code":                 "TEST-CODE",
			"verification_uri":          testServer.URL + "/device",
			"verification_uri_complete": testServer.URL + "/device?user_code=TEST-CODE",
			"expires_in":                600,
			"interval":                  5,
		})
	}))
	defer testServer.Close()

	serverURL = testServer.URL

	resp, err := requestDeviceCode(context.Background())
	if err != nil {
		t.Fatalf("requestDeviceCode() error: %v", err)
	}
	if resp.DeviceCode != "test-device-code" {
		t.Errorf("DeviceCode = %q, want %q", resp.DeviceCode, "test-device-code")
	}
	if attemptCount.Load() != 2 {
		t.Errorf("expected 2 attempts (1 retry), got %d", attemptCount.Load())
	}
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && findSubstring(s, sub)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
