package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// performBrowserFlow runs the Authorization Code Flow with PKCE.
//
// Returns:
//   - (storage, true, nil)  on success
//   - (nil, false, nil)     when openBrowser() fails — caller should fall back to Device Code Flow
//   - (nil, false, err)     on a hard error (CSRF mismatch, token exchange failure, etc.)
func performBrowserFlow() (*TokenStorage, bool, error) {
	state, err := generateState()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate state: %w", err)
	}

	pkce, err := GeneratePKCE()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	authURL := buildAuthURL(state, pkce)

	fmt.Println("Step 1: Opening browser for authorization...")
	fmt.Printf("\n  %s\n\n", authURL)

	if err := openBrowser(authURL); err != nil {
		// Browser failed to open — signal the caller to fall back immediately.
		fmt.Printf("Could not open browser: %v\n", err)
		return nil, false, nil
	}

	fmt.Println("Browser opened. Please complete authorization in your browser.")
	fmt.Printf("Step 2: Waiting for callback on http://localhost:%d/callback ...\n", callbackPort)

	code, err := startCallbackServer(callbackPort, state)
	if err != nil {
		if errors.Is(err, ErrCallbackTimeout) {
			// User opened the browser but didn't complete authorization in time.
			// Fall back to Device Code Flow so they can still authenticate.
			fmt.Printf(
				"Browser authorization timed out after %s, falling back to Device Code Flow...\n",
				callbackTimeout,
			)
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("authorization failed: %w", err)
	}
	fmt.Println("Authorization code received!")

	fmt.Println("Step 3: Exchanging authorization code for tokens...")
	storage, err := exchangeCode(code, pkce.Verifier)
	if err != nil {
		return nil, false, fmt.Errorf("token exchange failed: %w", err)
	}
	storage.Flow = "browser"

	if err := saveTokens(storage); err != nil {
		fmt.Printf("Warning: Failed to save tokens: %v\n", err)
	} else {
		fmt.Printf("Tokens saved to %s\n", tokenFile)
	}

	return storage, true, nil
}

// buildAuthURL constructs the /oauth/authorize URL with all required parameters.
func buildAuthURL(state string, pkce *PKCEParams) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("code_challenge", pkce.Challenge)
	params.Set("code_challenge_method", pkce.Method)
	return serverURL + "/oauth/authorize?" + params.Encode()
}

// exchangeCode exchanges an authorization code for access + refresh tokens.
func exchangeCode(code, codeVerifier string) (*TokenStorage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tokenExchangeTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)

	if isPublicClient() {
		data.Set("code_verifier", codeVerifier)
	} else {
		data.Set("client_secret", clientSecret)
		data.Set("code_verifier", codeVerifier)
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
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf(
			"token exchange failed with status %d: %s",
			resp.StatusCode,
			string(body),
		)
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

	return &TokenStorage{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		ClientID:     clientID,
	}, nil
}
