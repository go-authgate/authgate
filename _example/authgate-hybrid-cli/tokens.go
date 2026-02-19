package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ErrorResponse is an OAuth error payload.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ErrRefreshTokenExpired indicates the refresh token has expired or is invalid.
var ErrRefreshTokenExpired = fmt.Errorf("refresh token expired or invalid")

// TokenStorage holds persisted OAuth tokens for one client.
type TokenStorage struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	ClientID     string    `json:"client_id"`
	Flow         string    `json:"flow,omitempty"` // "browser" or "device"
}

// TokenStorageMap manages tokens for multiple clients in one file.
type TokenStorageMap struct {
	Tokens map[string]*TokenStorage `json:"tokens"`
}

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
		return nil, fmt.Errorf("no tokens in file")
	}
	if storage, ok := storageMap.Tokens[clientID]; ok {
		return storage, nil
	}
	return nil, fmt.Errorf("no tokens found for client_id: %s", clientID)
}

func saveTokens(storage *TokenStorage) error {
	if storage.ClientID == "" {
		storage.ClientID = clientID
	}

	lock, err := acquireFileLock(tokenFile)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer lock.release()

	var storageMap TokenStorageMap
	if existing, err := os.ReadFile(tokenFile); err == nil {
		if unmarshalErr := json.Unmarshal(existing, &storageMap); unmarshalErr != nil {
			storageMap.Tokens = make(map[string]*TokenStorage)
		}
	}
	if storageMap.Tokens == nil {
		storageMap.Tokens = make(map[string]*TokenStorage)
	}

	storageMap.Tokens[storage.ClientID] = storage

	data, err := json.MarshalIndent(storageMap, "", "  ")
	if err != nil {
		return err
	}

	tempFile := tokenFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0o600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := os.Rename(tempFile, tokenFile); err != nil {
		if removeErr := os.Remove(tempFile); removeErr != nil {
			return fmt.Errorf(
				"failed to rename temp file: %v; also failed to remove temp file: %w",
				err,
				removeErr,
			)
		}
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	return nil
}

// validateTokenResponse performs basic sanity checks on a token response.
func validateTokenResponse(accessToken, tokenType string, expiresIn int) error {
	if accessToken == "" {
		return fmt.Errorf("access_token is empty")
	}
	if len(accessToken) < 10 {
		return fmt.Errorf("access_token is too short (length: %d)", len(accessToken))
	}
	if expiresIn <= 0 {
		return fmt.Errorf("expires_in must be positive, got: %d", expiresIn)
	}
	if tokenType != "" && tokenType != "Bearer" {
		return fmt.Errorf("unexpected token_type: %s (expected Bearer)", tokenType)
	}
	return nil
}
