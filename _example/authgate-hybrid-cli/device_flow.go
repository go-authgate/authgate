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

	"golang.org/x/oauth2"
)

// performDeviceFlow runs the OAuth 2.0 Device Authorization Grant (RFC 8628)
// and returns tokens on success.
func performDeviceFlow(ctx context.Context) (*TokenStorage, error) {
	config := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: serverURL + "/oauth/device/code",
			TokenURL:      serverURL + "/oauth/token",
		},
		Scopes: strings.Fields(scope),
	}

	fmt.Println("Step 1: Requesting device code...")
	deviceAuth, err := requestDeviceCode(ctx)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}

	fmt.Printf("\n----------------------------------------\n")
	fmt.Printf("Please open this link to authorize:\n%s\n", deviceAuth.VerificationURIComplete)
	fmt.Printf("\nOr visit : %s\n", deviceAuth.VerificationURI)
	fmt.Printf("And enter: %s\n", deviceAuth.UserCode)
	fmt.Printf("----------------------------------------\n\n")

	fmt.Println("Step 2: Waiting for authorization...")
	token, err := pollForTokenWithProgress(ctx, config, deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("token poll failed: %w", err)
	}

	fmt.Println("\nAuthorization successful!")

	storage := &TokenStorage{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.Type(),
		ExpiresAt:    token.Expiry,
		ClientID:     clientID,
		Flow:         "device",
	}

	if err := saveTokens(storage); err != nil {
		fmt.Printf("Warning: Failed to save tokens: %v\n", err)
	} else {
		fmt.Printf("Tokens saved to %s\n", tokenFile)
	}

	return storage, nil
}

// requestDeviceCode requests a device code from the OAuth server.
func requestDeviceCode(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	reqCtx, cancel := context.WithTimeout(ctx, deviceCodeRequestTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", scope)

	req, err := http.NewRequestWithContext(
		reqCtx,
		http.MethodPost,
		serverURL+"/oauth/device/code",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := retryClient.Do(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"device code request failed with status %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	var deviceResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	return &oauth2.DeviceAuthResponse{
		DeviceCode:              deviceResp.DeviceCode,
		UserCode:                deviceResp.UserCode,
		VerificationURI:         deviceResp.VerificationURI,
		VerificationURIComplete: deviceResp.VerificationURIComplete,
		Expiry:                  time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second),
		Interval:                int64(deviceResp.Interval),
	}, nil
}

// pollForTokenWithProgress polls for a token while showing progress dots.
// Implements exponential backoff for slow_down errors per RFC 8628.
func pollForTokenWithProgress(
	ctx context.Context,
	config *oauth2.Config,
	deviceAuth *oauth2.DeviceAuthResponse,
) (*oauth2.Token, error) {
	interval := deviceAuth.Interval
	if interval == 0 {
		interval = 5
	}

	uiUpdateInterval := 2 * time.Second
	pollInterval := time.Duration(interval) * time.Second
	backoffMultiplier := 1.0

	ticker := time.NewTicker(uiUpdateInterval)
	defer ticker.Stop()

	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	dotCount := 0
	lastUpdate := time.Now()

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return nil, ctx.Err()

		case <-pollTicker.C:
			token, err := exchangeDeviceCode(
				ctx,
				config.Endpoint.TokenURL,
				config.ClientID,
				deviceAuth.DeviceCode,
			)
			if err != nil {
				var oauthErr *oauth2.RetrieveError
				if errors.As(err, &oauthErr) {
					var errResp ErrorResponse
					if jsonErr := json.Unmarshal(oauthErr.Body, &errResp); jsonErr == nil {
						switch errResp.Error {
						case "authorization_pending":
							continue

						case "slow_down":
							backoffMultiplier *= 1.5
							newInterval := time.Duration(float64(pollInterval) * backoffMultiplier)
							if newInterval > 60*time.Second {
								newInterval = 60 * time.Second
							}
							pollInterval = newInterval
							pollTicker.Reset(pollInterval)
							continue

						case "expired_token":
							fmt.Println()
							return nil, fmt.Errorf("device code expired, please restart the flow")

						case "access_denied":
							fmt.Println()
							return nil, fmt.Errorf("user denied authorization")

						default:
							fmt.Println()
							return nil, fmt.Errorf(
								"authorization failed: %s - %s",
								errResp.Error,
								errResp.ErrorDescription,
							)
						}
					}
				}
				fmt.Println()
				return nil, fmt.Errorf("token exchange failed: %w", err)
			}

			fmt.Println()
			return token, nil

		case <-ticker.C:
			if time.Since(lastUpdate) >= uiUpdateInterval {
				fmt.Print(".")
				dotCount++
				lastUpdate = time.Now()
				if dotCount%50 == 0 {
					fmt.Println()
				}
			}
		}
	}
}

// exchangeDeviceCode exchanges a device code for an access token.
func exchangeDeviceCode(
	ctx context.Context,
	tokenURL, cID, deviceCode string,
) (*oauth2.Token, error) {
	reqCtx, cancel := context.WithTimeout(ctx, tokenExchangeTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", cID)

	req, err := http.NewRequestWithContext(
		reqCtx,
		http.MethodPost,
		tokenURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := retryClient.Do(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
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

	return &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}, nil
}
