package token

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	retry "github.com/appleboy/go-httpretry"

	"github.com/appleboy/authgate/internal/config"
)

// HTTPTokenProvider generates and validates tokens via external HTTP API
type HTTPTokenProvider struct {
	config      *config.Config
	retryClient *retry.Client
}

// NewHTTPTokenProvider creates a new HTTP API token provider
func NewHTTPTokenProvider(cfg *config.Config, retryClient *retry.Client) *HTTPTokenProvider {
	return &HTTPTokenProvider{
		config:      cfg,
		retryClient: retryClient,
	}
}

// doPostRequest is a helper function to perform POST requests with JSON body
func (p *HTTPTokenProvider) doPostRequest(
	ctx context.Context,
	endpoint string,
	reqBody any,
) ([]byte, error) {
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := p.retryClient.Post(
		ctx,
		p.config.TokenAPIURL+endpoint,
		retry.WithBody("application/json", bytes.NewBuffer(jsonData)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPTokenConnection, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response", ErrHTTPTokenInvalidResp)
	}

	// Check HTTP status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return body, nil
}

// handleGenerateError handles error responses from token generation endpoints
func handleGenerateError(body []byte, statusCode string) error {
	var apiResp APITokenGenerateResponse
	if err := json.Unmarshal(body, &apiResp); err == nil && apiResp.Message != "" {
		return fmt.Errorf("%w: %s - %s", ErrHTTPTokenAuthFailed, statusCode, apiResp.Message)
	}
	bodyPreview := string(body)
	if len(bodyPreview) > 200 {
		bodyPreview = bodyPreview[:200] + "..."
	}
	return fmt.Errorf("%w: %s - %s", ErrHTTPTokenInvalidResp, statusCode, bodyPreview)
}

// parseGenerateResponse parses and validates token generation response
func parseGenerateResponse(body []byte) (*TokenResult, error) {
	var apiResp APITokenGenerateResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPTokenInvalidResp, err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("%w: %s", ErrHTTPTokenAuthFailed, apiResp.Message)
	}

	if apiResp.AccessToken == "" {
		return nil, fmt.Errorf(
			"%w: external API returned success=true but missing access_token",
			ErrHTTPTokenInvalidResp,
		)
	}

	tokenType := apiResp.TokenType
	if tokenType == "" {
		tokenType = TokenTypeBearer
	}

	expiresAt := time.Now().Add(time.Duration(apiResp.ExpiresIn) * time.Second)

	return &TokenResult{
		TokenString: apiResp.AccessToken,
		TokenType:   tokenType,
		ExpiresAt:   expiresAt,
		Claims:      apiResp.Claims,
		Success:     true,
	}, nil
}

// callValidateAPI is a helper function to validate tokens via HTTP API
func (p *HTTPTokenProvider) callValidateAPI(
	ctx context.Context,
	tokenString string,
	invalidErr, expiredErr error,
) (*TokenValidationResult, error) {
	reqBody := APITokenValidateRequest{
		Token: tokenString,
	}

	body, err := p.doPostRequest(ctx, "/validate", reqBody)
	if err != nil {
		// If we got a response body along with an error, the HTTP call reached the server
		// and the remote API reported a validation/HTTP error (for example, a 4xx status).
		// In that case, treat it as an "invalid token" condition rather than a transport failure.
		if body != nil {
			return nil, fmt.Errorf("%w: %s", invalidErr, err.Error())
		}
		return nil, err
	}

	var apiResp APITokenValidateResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPTokenInvalidResp, err)
	}

	if !apiResp.Valid {
		return nil, invalidErr
	}

	var expiresAt time.Time
	if apiResp.ExpiresAt > 0 {
		expiresAt = time.Unix(apiResp.ExpiresAt, 0)
		if time.Now().After(expiresAt) {
			return nil, expiredErr
		}
	}

	return &TokenValidationResult{
		Valid:     true,
		UserID:    apiResp.UserID,
		ClientID:  apiResp.ClientID,
		Scopes:    apiResp.Scopes,
		ExpiresAt: expiresAt,
		Claims:    apiResp.Claims,
	}, nil
}

// APITokenGenerateRequest is the request payload for token generation
type APITokenGenerateRequest struct {
	UserID    string `json:"user_id"`
	ClientID  string `json:"client_id"`
	Scopes    string `json:"scopes"`
	ExpiresIn int    `json:"expires_in,omitempty"` // seconds
}

// APITokenGenerateResponse is the expected response for token generation
type APITokenGenerateResponse struct {
	Success     bool           `json:"success"`
	AccessToken string         `json:"access_token,omitempty"`
	TokenType   string         `json:"token_type,omitempty"`
	ExpiresIn   int            `json:"expires_in,omitempty"` // seconds
	Claims      map[string]any `json:"claims,omitempty"`
	Message     string         `json:"message,omitempty"`
}

// APITokenValidateRequest is the request payload for token validation
type APITokenValidateRequest struct {
	Token string `json:"token"`
}

// APITokenValidateResponse is the expected response for token validation
type APITokenValidateResponse struct {
	Valid     bool           `json:"valid"`
	UserID    string         `json:"user_id,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	Scopes    string         `json:"scopes,omitempty"`
	ExpiresAt int64          `json:"expires_at,omitempty"` // Unix timestamp
	Claims    map[string]any `json:"claims,omitempty"`
	Message   string         `json:"message,omitempty"`
}

// generateTokenInternal is a helper to generate tokens with custom expiration
func (p *HTTPTokenProvider) generateTokenInternal(
	ctx context.Context,
	userID, clientID, scopes string,
	expiration time.Duration,
) (*TokenResult, error) {
	reqBody := APITokenGenerateRequest{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresIn: int(expiration.Seconds()),
	}

	body, err := p.doPostRequest(ctx, "/generate", reqBody)
	if err != nil {
		// Check if we got a response body (indicates HTTP error vs connection error)
		if body != nil {
			return nil, handleGenerateError(body, err.Error())
		}
		return nil, err
	}

	return parseGenerateResponse(body)
}

// GenerateToken requests token generation from external API
func (p *HTTPTokenProvider) GenerateToken(
	ctx context.Context,
	userID, clientID, scopes string,
) (*TokenResult, error) {
	return p.generateTokenInternal(ctx, userID, clientID, scopes, p.config.JWTExpiration)
}

// ValidateToken requests token validation from external API
func (p *HTTPTokenProvider) ValidateToken(
	ctx context.Context,
	tokenString string,
) (*TokenValidationResult, error) {
	return p.callValidateAPI(ctx, tokenString, ErrInvalidToken, ErrExpiredToken)
}

// Name returns provider name for logging
func (p *HTTPTokenProvider) Name() string {
	return "http_api"
}

// APIRefreshRequest is the request payload for refresh token operations
type APIRefreshRequest struct {
	RefreshToken   string `json:"refresh_token"`
	UserID         string `json:"user_id"`
	ClientID       string `json:"client_id"`
	Scopes         string `json:"scopes"`
	EnableRotation bool   `json:"enable_rotation"`
}

// APIRefreshResponse is the expected response for refresh token operations
type APIRefreshResponse struct {
	Success          bool           `json:"success"`
	AccessToken      string         `json:"access_token,omitempty"`
	RefreshToken     string         `json:"refresh_token,omitempty"`
	TokenType        string         `json:"token_type,omitempty"`
	AccessExpiresIn  int            `json:"access_expires_in,omitempty"`
	RefreshExpiresIn int            `json:"refresh_expires_in,omitempty"`
	Claims           map[string]any `json:"claims,omitempty"`
	Message          string         `json:"message,omitempty"`
}

// GenerateRefreshToken requests refresh token generation from external API
func (p *HTTPTokenProvider) GenerateRefreshToken(
	ctx context.Context,
	userID, clientID, scopes string,
) (*TokenResult, error) {
	return p.generateTokenInternal(ctx, userID, clientID, scopes, p.config.RefreshTokenExpiration)
}

// ValidateRefreshToken requests refresh token validation from external API
func (p *HTTPTokenProvider) ValidateRefreshToken(
	ctx context.Context,
	tokenString string,
) (*TokenValidationResult, error) {
	return p.callValidateAPI(ctx, tokenString, ErrInvalidRefreshToken, ErrExpiredRefreshToken)
}

// RefreshAccessToken requests new access token (and optionally new refresh token) from external API
func (p *HTTPTokenProvider) RefreshAccessToken(
	ctx context.Context,
	refreshToken string,
	enableRotation bool,
) (*RefreshResult, error) {
	// First validate to get user/client info
	validationResult, err := p.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	reqBody := APIRefreshRequest{
		RefreshToken:   refreshToken,
		UserID:         validationResult.UserID,
		ClientID:       validationResult.ClientID,
		Scopes:         validationResult.Scopes,
		EnableRotation: enableRotation,
	}

	body, err := p.doPostRequest(ctx, "/refresh", reqBody)
	if err != nil {
		// Check if we got a response body (indicates HTTP error vs connection error)
		if body != nil {
			var apiResp APIRefreshResponse
			if unmarshalErr := json.Unmarshal(body, &apiResp); unmarshalErr == nil &&
				apiResp.Message != "" {
				return nil, fmt.Errorf(
					"%w: %s - %s",
					ErrHTTPTokenAuthFailed,
					err.Error(),
					apiResp.Message,
				)
			}
			return nil, fmt.Errorf("%w: %s", ErrHTTPTokenInvalidResp, err.Error())
		}
		return nil, err
	}

	var apiResp APIRefreshResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPTokenInvalidResp, err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("%w: %s", ErrHTTPTokenAuthFailed, apiResp.Message)
	}

	if apiResp.AccessToken == "" {
		return nil, fmt.Errorf(
			"%w: external API returned success=true but missing access_token",
			ErrHTTPTokenInvalidResp,
		)
	}

	tokenType := apiResp.TokenType
	if tokenType == "" {
		tokenType = TokenTypeBearer
	}

	accessExpiresAt := time.Now().Add(time.Duration(apiResp.AccessExpiresIn) * time.Second)

	result := &RefreshResult{
		AccessToken: &TokenResult{
			TokenString: apiResp.AccessToken,
			TokenType:   tokenType,
			ExpiresAt:   accessExpiresAt,
			Claims:      apiResp.Claims,
			Success:     true,
		},
		Success: true,
	}

	// If rotation is enabled and new refresh token is provided
	if enableRotation && apiResp.RefreshToken != "" {
		refreshExpiresAt := time.Now().Add(time.Duration(apiResp.RefreshExpiresIn) * time.Second)
		result.RefreshToken = &TokenResult{
			TokenString: apiResp.RefreshToken,
			TokenType:   tokenType,
			ExpiresAt:   refreshExpiresAt,
			Claims:      apiResp.Claims,
			Success:     true,
		}
	}

	return result, nil
}
