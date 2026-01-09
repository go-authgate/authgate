package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	serverURL string
	clientID  string
)

func init() {
	// Load .env file if exists (ignore error if not found)
	_ = godotenv.Load()

	serverURL = getEnv("SERVER_URL", "http://localhost:8080")
	clientID = getEnv("CLIENT_ID", "")

	if clientID == "" {
		fmt.Println("Error: CLIENT_ID not set. Please set it in .env file or environment variable.")
		fmt.Println("You can find the client_id in the server startup logs.")
		os.Exit(1)
	}
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

func main() {
	fmt.Printf("=== OAuth Device Code Flow CLI Demo ===\n")

	// Configure OAuth2 with device flow endpoints
	config := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: serverURL + "/oauth/device/code",
			TokenURL:      serverURL + "/oauth/token",
		},
		Scopes: []string{"read", "write"},
	}

	ctx := context.Background()

	// Step 1: Request device code
	fmt.Println("Step 1: Requesting device code...")
	deviceAuth, err := config.DeviceAuth(ctx)
	if err != nil {
		fmt.Printf("Error requesting device code: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n----------------------------------------\n")
	fmt.Printf("Please open this link to authorize:\n%s\n", deviceAuth.VerificationURIComplete)
	fmt.Printf("\nOr manually visit: %s\n", deviceAuth.VerificationURI)
	fmt.Printf("And enter code: %s\n", deviceAuth.UserCode)
	fmt.Printf("----------------------------------------\n\n")

	// Step 2: Poll for token with custom polling logic to show progress
	fmt.Println("Step 2: Waiting for authorization...")
	token, err := pollForTokenWithProgress(ctx, config, deviceAuth)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("Authorization successful!\n")
	fmt.Printf("Access Token: %s...\n", token.AccessToken[:min(50, len(token.AccessToken))])
	fmt.Printf("Token Type: %s\n", token.Type())
	fmt.Printf("Expires In: %s\n", time.Until(token.Expiry).Round(time.Second))
	fmt.Printf("========================================\n")

	// Step 3: Verify token
	fmt.Println("\nStep 3: Verifying token...")
	if err := verifyToken(token.AccessToken); err != nil {
		fmt.Printf("Token verification failed: %v\n", err)
	} else {
		fmt.Println("Token verified successfully!")
	}
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
