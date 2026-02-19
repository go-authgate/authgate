package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	initConfig()

	clientMode := "public (PKCE)"
	if !isPublicClient() {
		clientMode = "confidential"
	}
	fmt.Printf("=== AuthGate Hybrid CLI (Browser + Device Code Flow) ===\n")
	fmt.Printf("Client mode : %s\n", clientMode)
	fmt.Printf("Server URL  : %s\n", serverURL)
	fmt.Printf("Client ID   : %s\n", clientID)
	fmt.Println()

	ctx := context.Background()
	var storage *TokenStorage

	// Try to reuse or refresh existing tokens.
	existing, err := loadTokens()
	if err == nil && existing != nil {
		fmt.Println("Found existing tokens.")
		if time.Now().Before(existing.ExpiresAt) {
			fmt.Println("Access token is still valid, using it.")
			storage = existing
		} else {
			fmt.Println("Access token expired, attempting refresh...")
			newStorage, err := refreshAccessToken(existing.RefreshToken)
			if err != nil {
				fmt.Printf("Refresh failed: %v\n", err)
				fmt.Println("Starting new authentication flow...")
			} else {
				storage = newStorage
				fmt.Println("Token refreshed successfully.")
			}
		}
	} else {
		fmt.Println("No existing tokens found, starting authentication flow...")
	}

	// No valid tokens — select and run the appropriate flow.
	if storage == nil {
		storage, err = authenticate(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Display token info.
	fmt.Printf("\n========================================\n")
	fmt.Printf("Current Token Info:\n")
	preview := storage.AccessToken
	if len(preview) > 50 {
		preview = preview[:50]
	}
	fmt.Printf("Access Token : %s...\n", preview)
	fmt.Printf("Token Type   : %s\n", storage.TokenType)
	fmt.Printf("Expires In   : %s\n", time.Until(storage.ExpiresAt).Round(time.Second))
	if storage.Flow != "" {
		fmt.Printf("Auth Flow    : %s\n", storage.Flow)
	}
	fmt.Printf("========================================\n")

	// Verify token against server.
	fmt.Println("\nVerifying token with server...")
	if err := verifyToken(storage.AccessToken); err != nil {
		fmt.Printf("Token verification failed: %v\n", err)
	} else {
		fmt.Println("Token verified successfully.")
	}

	// Demonstrate auto-refresh on 401.
	fmt.Println("\nDemonstrating automatic refresh on API call...")
	if err := makeAPICallWithAutoRefresh(ctx, storage); err != nil {
		if err == ErrRefreshTokenExpired {
			fmt.Println("Refresh token expired, re-authenticating...")
			storage, err = authenticate(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Re-authentication failed: %v\n", err)
				os.Exit(1)
			}
			if err := makeAPICallWithAutoRefresh(ctx, storage); err != nil {
				fmt.Fprintf(os.Stderr, "API call failed after re-authentication: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("API call successful after re-authentication.")
		} else {
			fmt.Fprintf(os.Stderr, "API call failed: %v\n", err)
		}
	}
}

// authenticate selects and runs the appropriate OAuth flow:
//
//  1. --device / --no-browser flag → Device Code Flow (forced)
//  2. Environment signals (SSH, no display, port busy) → Device Code Flow
//  3. Browser available → Authorization Code Flow with PKCE
//     - openBrowser() error → immediate fallback to Device Code Flow
func authenticate(ctx context.Context) (*TokenStorage, error) {
	if forceDevice {
		fmt.Println("Auth method : Device Code Flow (forced via flag)")
		return performDeviceFlow(ctx)
	}

	avail := checkBrowserAvailability(callbackPort)
	if !avail.Available {
		fmt.Printf("Auth method : Device Code Flow (%s)\n", avail.Reason)
		return performDeviceFlow(ctx)
	}

	fmt.Println("Auth method : Authorization Code Flow (browser)")
	storage, ok, err := performBrowserFlow()
	if err != nil {
		return nil, err
	}
	if !ok {
		// openBrowser() failed; fall back to Device Code Flow immediately.
		fmt.Println("Auth method : Device Code Flow (browser unavailable)")
		return performDeviceFlow(ctx)
	}
	return storage, nil
}

// -----------------------------------------------------------------------
// Token refresh
// -----------------------------------------------------------------------

func refreshAccessToken(refreshToken string) (*TokenStorage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTokenTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	if !isPublicClient() {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		serverURL+"/oauth/token",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := retryClient.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil {
			if errResp.Error == "invalid_grant" || errResp.Error == "invalid_token" {
				return nil, ErrRefreshTokenExpired
			}
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if err := validateTokenResponse(
		tokenResp.AccessToken,
		tokenResp.TokenType,
		tokenResp.ExpiresIn,
	); err != nil {
		return nil, fmt.Errorf("invalid token response: %w", err)
	}

	// Preserve the old refresh token in fixed-mode (server may not return a new one).
	newRefreshToken := tokenResp.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}

	storage := &TokenStorage{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		ClientID:     clientID,
	}

	if err := saveTokens(storage); err != nil {
		fmt.Printf("Warning: Failed to save refreshed tokens: %v\n", err)
	}
	return storage, nil
}

// -----------------------------------------------------------------------
// Token verification / API demo
// -----------------------------------------------------------------------

func verifyToken(accessToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), tokenVerificationTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/oauth/tokeninfo", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := retryClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil {
			return fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Token Info: %s\n", string(body))
	return nil
}

// makeAPICallWithAutoRefresh demonstrates the 401 → refresh → retry pattern.
func makeAPICallWithAutoRefresh(ctx context.Context, storage *TokenStorage) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/oauth/tokeninfo", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+storage.AccessToken)

	resp, err := retryClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Access token rejected (401), refreshing...")

		newStorage, err := refreshAccessToken(storage.RefreshToken)
		if err != nil {
			if err == ErrRefreshTokenExpired {
				return ErrRefreshTokenExpired
			}
			return fmt.Errorf("refresh failed: %w", err)
		}

		storage.AccessToken = newStorage.AccessToken
		storage.RefreshToken = newStorage.RefreshToken
		storage.ExpiresAt = newStorage.ExpiresAt

		fmt.Println("Token refreshed, retrying API call...")

		req, err = http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			serverURL+"/oauth/tokeninfo",
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to create retry request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+storage.AccessToken)

		resp, err = retryClient.Do(ctx, req)
		if err != nil {
			return fmt.Errorf("retry failed: %w", err)
		}
		defer resp.Body.Close()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API call failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("API call successful!")
	return nil
}
