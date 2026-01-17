package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	httpclient "github.com/appleboy/go-httpclient"

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

	// Create HTTP client with automatic authentication
	client := httpclient.NewAuthClient(
		cfg.HTTPAPIAuthMode,
		cfg.HTTPAPIAuthSecret,
		httpclient.WithTimeout(cfg.HTTPAPITimeout),
		httpclient.WithTransport(transport),
		httpclient.WithHeaderName(cfg.HTTPAPIAuthHeader),
	)

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
func (p *HTTPAPIAuthProvider) Authenticate(
	ctx context.Context,
	username, password string,
) (*AuthResult, error) {
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

	// Authentication headers are automatically added by the HTTP client
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPAPIConnection, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response", ErrHTTPAPIInvalidResp)
	}

	// Check HTTP status code before attempting to parse JSON
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to parse as JSON to get error message
		var authResp APIAuthResponse
		if err := json.Unmarshal(body, &authResp); err == nil {
			// Valid JSON response with error
			if authResp.Message != "" {
				return nil, fmt.Errorf(
					"%w: HTTP %d - %s",
					ErrHTTPAPIAuthFailed,
					resp.StatusCode,
					authResp.Message,
				)
			}
		}
		// Non-JSON or missing message, return generic error with status code
		// Limit body preview to 200 characters to avoid overwhelming logs
		bodyPreview := string(body)
		if len(bodyPreview) > 200 {
			bodyPreview = bodyPreview[:200] + "..."
		}
		return nil, fmt.Errorf(
			"%w: HTTP %d - %s",
			ErrHTTPAPIInvalidResp,
			resp.StatusCode,
			bodyPreview,
		)
	}

	var authResp APIAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPAPIInvalidResp, err)
	}

	if !authResp.Success {
		return nil, ErrHTTPAPIAuthFailed
	}

	// Validate that user_id is provided when authentication succeeds
	if authResp.UserID == "" {
		return nil, fmt.Errorf(
			"%w: external API returned success=true but missing user_id",
			ErrHTTPAPIInvalidResp,
		)
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
