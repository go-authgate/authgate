package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	serverURL = "http://localhost:8080"
	clientID  = "cli-tool"
)

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func main() {
	fmt.Printf("=== OAuth Device Code Flow CLI Demo ===\n")

	// Step 1: Request device code
	fmt.Println("Step 1: Requesting device code...")
	deviceCode, err := requestDeviceCode()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n----------------------------------------\n")
	fmt.Printf("Please visit: %s\n", deviceCode.VerificationURI)
	fmt.Printf("And enter code: %s\n", deviceCode.UserCode)
	fmt.Printf("----------------------------------------\n\n")

	// Step 2: Poll for token
	fmt.Println("Step 2: Waiting for authorization...")
	token, err := pollForToken(deviceCode.DeviceCode, deviceCode.Interval)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("Authorization successful!\n")
	fmt.Printf("Access Token: %s...\n", token.AccessToken[:50])
	fmt.Printf("Token Type: %s\n", token.TokenType)
	fmt.Printf("Expires In: %d seconds\n", token.ExpiresIn)
	fmt.Printf("Scope: %s\n", token.Scope)
	fmt.Printf("========================================\n")

	// Step 3: Verify token
	fmt.Println("\nStep 3: Verifying token...")
	if err := verifyToken(token.AccessToken); err != nil {
		fmt.Printf("Token verification failed: %v\n", err)
	} else {
		fmt.Println("Token verified successfully!")
	}
}

func requestDeviceCode() (*DeviceCodeResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "read write")

	resp, err := http.Post(serverURL+"/oauth/device/code", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
	}

	var deviceCode DeviceCodeResponse
	if err := json.Unmarshal(body, &deviceCode); err != nil {
		return nil, err
	}

	return &deviceCode, nil
}

func pollForToken(deviceCode string, interval int) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", clientID)

	for {
		resp, err := http.Post(serverURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			var token TokenResponse
			if err := json.Unmarshal(body, &token); err != nil {
				return nil, err
			}
			return &token, nil
		}

		var errResp ErrorResponse
		json.Unmarshal(body, &errResp)

		switch errResp.Error {
		case "authorization_pending":
			fmt.Print(".")
			time.Sleep(time.Duration(interval) * time.Second)
		case "slow_down":
			interval++
			time.Sleep(time.Duration(interval) * time.Second)
		case "expired_token":
			return nil, fmt.Errorf("device code expired, please try again")
		case "access_denied":
			return nil, fmt.Errorf("access denied by user")
		default:
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
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
