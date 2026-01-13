package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/appleboy/authgate/internal/config"
)

// HTTPAPIAuthProvider handles HTTP API-based authentication
type HTTPAPIAuthProvider struct {
	config *config.Config
	client *http.Client
}

// NewHTTPAPIAuthProvider creates a new HTTP API authentication provider
func NewHTTPAPIAuthProvider(cfg *config.Config) *HTTPAPIAuthProvider {
	// #nosec G402 -- InsecureSkipVerify is user-configurable for development/testing
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.HTTPAPIInsecureSkipVerify,
		},
	}

	client := &http.Client{
		Timeout:   cfg.HTTPAPITimeout,
		Transport: transport,
	}

	return &HTTPAPIAuthProvider{
		config: cfg,
		client: client,
	}
}

// APIAuthRequest is the request payload sent to external API
type APIAuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// APIAuthResponse is the expected response from external API
type APIAuthResponse struct {
	Success  bool   `json:"success"`
	UserID   string `json:"user_id,omitempty"`
	Email    string `json:"email,omitempty"`
	FullName string `json:"full_name,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Authenticate verifies credentials against external HTTP API
func (p *HTTPAPIAuthProvider) Authenticate(ctx context.Context, username, password string) (*AuthResult, error) {
	reqBody := APIAuthRequest{
		Username: username,
		Password: password,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		p.config.HTTPAPIURL,
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPAPIConnection, err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPAPIConnection, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response", ErrHTTPAPIInvalidResp)
	}

	var authResp APIAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPAPIInvalidResp, err)
	}

	if !authResp.Success {
		return nil, ErrHTTPAPIAuthFailed
	}

	return &AuthResult{
		Username:   username,
		ExternalID: authResp.UserID,
		Email:      authResp.Email,
		FullName:   authResp.FullName,
		Success:    true,
	}, nil
}

// Name returns provider name for logging
func (p *HTTPAPIAuthProvider) Name() string {
	return "http_api"
}
