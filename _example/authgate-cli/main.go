package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	serverURL string
	clientID  string
	tokenFile string
)

func init() {
	// Load .env file if exists (ignore error if not found)
	_ = godotenv.Load()

	// Define flags
	flagServerURL := flag.String("server-url", "", "OAuth server URL (default: http://localhost:8080 or SERVER_URL env)")
	flagClientID := flag.String("client-id", "", "OAuth client ID (required, or set CLIENT_ID env)")
	flagTokenFile := flag.String("token-file", "", "Token storage file (default: .authgate-tokens.json or TOKEN_FILE env)")
	flag.Parse()

	// Priority: flag > env > default
	serverURL = getConfig(*flagServerURL, "SERVER_URL", "http://localhost:8080")
	clientID = getConfig(*flagClientID, "CLIENT_ID", "")
	tokenFile = getConfig(*flagTokenFile, "TOKEN_FILE", ".authgate-tokens.json")

	if clientID == "" {
		fmt.Println("Error: CLIENT_ID not set. Please provide it via:")
		fmt.Println("  1. Command line flag: -client-id=<your-client-id>")
		fmt.Println("  2. Environment variable: CLIENT_ID=<your-client-id>")
		fmt.Println("  3. .env file: CLIENT_ID=<your-client-id>")
		fmt.Println("\nYou can find the client_id in the server startup logs.")
		os.Exit(1)
	}
}

// getConfig returns value with priority: flag > env > default
func getConfig(flagValue, envKey, defaultValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return getEnv(envKey, defaultValue)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ErrRefreshTokenExpired indicates that the refresh token has expired or is invalid
var ErrRefreshTokenExpired = fmt.Errorf("refresh token expired or invalid")

// TokenStorage represents saved tokens for a specific client
type TokenStorage struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	ClientID     string    `json:"client_id"`
}

// TokenStorageMap manages tokens for multiple clients
type TokenStorageMap struct {
	Tokens map[string]*TokenStorage `json:"tokens"` // key = client_id
}

func main() {
	fmt.Printf("=== OAuth Device Code Flow CLI Demo (with Refresh Token) ===\n\n")

	ctx := context.Background()
	var storage *TokenStorage

	// Try to load existing tokens
	storage, err := loadTokens()
	if err == nil && storage != nil {
		fmt.Println("Found existing tokens!")

		// Check if access token is still valid
		if time.Now().Before(storage.ExpiresAt) {
			fmt.Println("Access token is still valid, using it...")
		} else {
			fmt.Println("Access token expired, refreshing...")

			// Try to refresh
			newStorage, err := refreshAccessToken(storage.RefreshToken)
			if err != nil {
				fmt.Printf("Refresh failed: %v\n", err)
				fmt.Println("Starting new device flow...")
				storage = nil // Force device flow
			} else {
				storage = newStorage
				fmt.Println("Token refreshed successfully!")
			}
		}
	} else {
		fmt.Println("No existing tokens found, starting device flow...")
	}

	// If no valid tokens, do device flow
	if storage == nil {
		storage, err = performDeviceFlow(ctx)
		if err != nil {
			fmt.Printf("Device flow failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Display current token info
	fmt.Printf("\n========================================\n")
	fmt.Printf("Current Token Info:\n")
	tokenPreview := storage.AccessToken
	if len(tokenPreview) > 50 {
		tokenPreview = tokenPreview[:50]
	}
	fmt.Printf("Access Token: %s...\n", tokenPreview)
	fmt.Printf("Token Type: %s\n", storage.TokenType)
	fmt.Printf("Expires In: %s\n", time.Until(storage.ExpiresAt).Round(time.Second))
	fmt.Printf("========================================\n")

	// Verify token
	fmt.Println("\nVerifying token...")
	if err := verifyToken(storage.AccessToken); err != nil {
		fmt.Printf("Token verification failed: %v\n", err)
	} else {
		fmt.Println("Token verified successfully!")
	}

	// Demonstrate automatic refresh on 401
	fmt.Println("\nDemonstrating automatic refresh on API call...")
	if err := makeAPICallWithAutoRefresh(storage); err != nil {
		// Check if error is due to expired refresh token
		if err == ErrRefreshTokenExpired {
			fmt.Println("Refresh token expired, re-authenticating...")
			storage, err = performDeviceFlow(ctx)
			if err != nil {
				fmt.Printf("Re-authentication failed: %v\n", err)
				os.Exit(1)
			}

			// Retry API call with new tokens
			fmt.Println("Retrying API call with new tokens...")
			if err := makeAPICallWithAutoRefresh(storage); err != nil {
				fmt.Printf("API call failed after re-authentication: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("API call successful after re-authentication!")
		} else {
			fmt.Printf("API call failed: %v\n", err)
		}
	}
}

// performDeviceFlow performs the OAuth device authorization flow
func performDeviceFlow(ctx context.Context) (*TokenStorage, error) {
	config := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: serverURL + "/oauth/device/code",
			TokenURL:      serverURL + "/oauth/token",
		},
		Scopes: []string{"read", "write"},
	}

	// Step 1: Request device code
	fmt.Println("Step 1: Requesting device code...")
	deviceAuth, err := config.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}

	fmt.Printf("\n----------------------------------------\n")
	fmt.Printf("Please open this link to authorize:\n%s\n", deviceAuth.VerificationURIComplete)
	fmt.Printf("\nOr manually visit: %s\n", deviceAuth.VerificationURI)
	fmt.Printf("And enter code: %s\n", deviceAuth.UserCode)
	fmt.Printf("----------------------------------------\n\n")

	// Step 2: Poll for token
	fmt.Println("Step 2: Waiting for authorization...")
	token, err := pollForTokenWithProgress(ctx, config, deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("token poll failed: %w", err)
	}

	fmt.Println("\nAuthorization successful!")

	// Convert to TokenStorage and save
	storage := &TokenStorage{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.Type(),
		ExpiresAt:    token.Expiry,
		ClientID:     clientID,
	}

	if err := saveTokens(storage); err != nil {
		fmt.Printf("Warning: Failed to save tokens: %v\n", err)
	} else {
		fmt.Printf("Tokens saved to %s\n", tokenFile)
	}

	return storage, nil
}

// pollForTokenWithProgress polls for token while showing progress dots
func pollForTokenWithProgress(
	ctx context.Context,
	config *oauth2.Config,
	deviceAuth *oauth2.DeviceAuthResponse,
) (*oauth2.Token, error) {
	// Create a channel to receive the token
	tokenChan := make(chan *oauth2.Token, 1)
	errChan := make(chan error, 1)

	// Start polling in a goroutine
	go func() {
		token, err := config.DeviceAccessToken(ctx, deviceAuth)
		if err != nil {
			errChan <- err
			return
		}
		tokenChan <- token
	}()

	// Show progress dots while waiting
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case token := <-tokenChan:
			fmt.Println() // New line after dots
			return token, nil
		case err := <-errChan:
			fmt.Println() // New line after dots
			return nil, err
		case <-ticker.C:
			fmt.Print(".")
		}
	}
}

func verifyToken(accessToken string) error {
	req, _ := http.NewRequest("GET", serverURL+"/oauth/tokeninfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		json.Unmarshal(body, &errResp)
		return fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
	}

	fmt.Printf("Token Info: %s\n", string(body))
	return nil
}

// loadTokens loads tokens from file for the current client
func loadTokens() (*TokenStorage, error) {
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	var storageMap TokenStorageMap
	if err := json.Unmarshal(data, &storageMap); err != nil {
		return nil, fmt.Errorf("failed to parse token file: %w", err)
	}

	if storageMap.Tokens == nil {
		return nil, fmt.Errorf("no tokens found in token file")
	}

	// Look up token for current client_id
	if storage, ok := storageMap.Tokens[clientID]; ok {
		return storage, nil
	}

	return nil, fmt.Errorf("no tokens found for client_id: %s", clientID)
}

// saveTokens saves tokens to file (merges with existing tokens for other clients)
func saveTokens(storage *TokenStorage) error {
	// Ensure ClientID is set
	if storage.ClientID == "" {
		storage.ClientID = clientID
	}

	// Load existing token map
	var storageMap TokenStorageMap
	existingData, err := os.ReadFile(tokenFile)
	if err == nil {
		// File exists, try to load it
		if unmarshalErr := json.Unmarshal(existingData, &storageMap); unmarshalErr != nil {
			// If unmarshal fails, start with empty map
			storageMap.Tokens = make(map[string]*TokenStorage)
		}
	}

	// Initialize map if nil
	if storageMap.Tokens == nil {
		storageMap.Tokens = make(map[string]*TokenStorage)
	}

	// Add or update token for current client
	storageMap.Tokens[storage.ClientID] = storage

	// Marshal and save
	data, err := json.MarshalIndent(storageMap, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(tokenFile, data, 0o600) // 0600 = read/write for owner only
}

// refreshAccessToken refreshes the access token using refresh token
func refreshAccessToken(refreshToken string) (*TokenStorage, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)

	resp, err := http.PostForm(serverURL+"/oauth/token", data)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			// Check if refresh token is expired or invalid
			if errResp.Error == "invalid_grant" || errResp.Error == "invalid_token" {
				return nil, ErrRefreshTokenExpired
			}
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("refresh failed with status %d", resp.StatusCode)
	}

	// Parse token response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	storage := &TokenStorage{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		ClientID:     clientID,
	}

	// Save updated tokens
	if err := saveTokens(storage); err != nil {
		fmt.Printf("Warning: Failed to save refreshed tokens: %v\n", err)
	}

	return storage, nil
}

// makeAPICallWithAutoRefresh demonstrates automatic refresh on 401
func makeAPICallWithAutoRefresh(storage *TokenStorage) error {
	// Try with current access token
	req, _ := http.NewRequest("GET", serverURL+"/oauth/tokeninfo", nil)
	req.Header.Set("Authorization", "Bearer "+storage.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// If 401, try to refresh and retry
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Access token rejected (401), refreshing...")

		newStorage, err := refreshAccessToken(storage.RefreshToken)
		if err != nil {
			// If refresh token is expired, propagate the error to trigger device flow
			if err == ErrRefreshTokenExpired {
				return ErrRefreshTokenExpired
			}
			return fmt.Errorf("refresh failed: %w", err)
		}

		// Update storage and retry
		storage.AccessToken = newStorage.AccessToken
		storage.RefreshToken = newStorage.RefreshToken
		storage.ExpiresAt = newStorage.ExpiresAt

		fmt.Println("Token refreshed, retrying API call...")

		// Retry with new token
		req, _ = http.NewRequest("GET", serverURL+"/oauth/tokeninfo", nil)
		req.Header.Set("Authorization", "Bearer "+storage.AccessToken)

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("retry failed: %w", err)
		}
		defer resp.Body.Close()
	}

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API call failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("API call successful!")
	return nil
}
