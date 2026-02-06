package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/token"

	"github.com/google/uuid"
)

// TokenWithClient combines token and client information for display
type TokenWithClient struct {
	models.AccessToken
	ClientName string
}

var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
)

type TokenService struct {
	store              *store.Store
	config             *config.Config
	deviceService      *DeviceService
	localTokenProvider *token.LocalTokenProvider
	httpTokenProvider  *token.HTTPTokenProvider
	tokenProviderMode  string
	auditService       *AuditService
}

func NewTokenService(
	s *store.Store,
	cfg *config.Config,
	ds *DeviceService,
	localProvider *token.LocalTokenProvider,
	httpProvider *token.HTTPTokenProvider,
	providerMode string,
	auditService *AuditService,
) *TokenService {
	return &TokenService{
		store:              s,
		config:             cfg,
		deviceService:      ds,
		localTokenProvider: localProvider,
		httpTokenProvider:  httpProvider,
		tokenProviderMode:  providerMode,
		auditService:       auditService,
	}
}

// ExchangeDeviceCode exchanges an authorized device code for access and refresh tokens
func (s *TokenService) ExchangeDeviceCode(
	ctx context.Context,
	deviceCode, clientID string,
) (*models.AccessToken, *models.AccessToken, error) {
	dc, err := s.deviceService.GetDeviceCode(deviceCode)
	if err != nil {
		if errors.Is(err, ErrDeviceCodeExpired) {
			return nil, nil, ErrExpiredToken
		}
		return nil, nil, ErrExpiredToken
	}

	// Check if client matches
	if dc.ClientID != clientID {
		return nil, nil, ErrAccessDenied
	}

	// Check if client is active
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return nil, nil, ErrAccessDenied
	}
	if !client.IsActive {
		return nil, nil, ErrAccessDenied
	}

	// Check if authorized
	if !dc.Authorized {
		return nil, nil, ErrAuthorizationPending
	}

	// Generate access token using provider
	var accessTokenResult *token.TokenResult
	var providerErr error

	switch s.tokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		if s.httpTokenProvider == nil {
			return nil, nil, fmt.Errorf(
				"HTTP token provider not configured (TOKEN_PROVIDER_MODE=http_api requires TOKEN_API_URL)",
			)
		}
		accessTokenResult, providerErr = s.httpTokenProvider.GenerateToken(
			ctx,
			dc.UserID,
			dc.ClientID,
			dc.Scopes,
		)
	case config.TokenProviderModeLocal:
		fallthrough
	default:
		if s.localTokenProvider == nil {
			return nil, nil, fmt.Errorf("local token provider not configured")
		}
		accessTokenResult, providerErr = s.localTokenProvider.GenerateToken(
			ctx,
			dc.UserID,
			dc.ClientID,
			dc.Scopes,
		)
	}

	if providerErr != nil {
		log.Printf(
			"[Token] Access token generation failed provider=%s: %v",
			s.tokenProviderMode,
			providerErr,
		)
		return nil, nil, fmt.Errorf("token generation failed: %w", providerErr)
	}

	if !accessTokenResult.Success {
		return nil, nil, fmt.Errorf("token generation unsuccessful")
	}

	// Generate refresh token using provider
	var refreshTokenResult *token.TokenResult

	switch s.tokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		refreshTokenResult, providerErr = s.httpTokenProvider.GenerateRefreshToken(
			ctx,
			dc.UserID,
			dc.ClientID,
			dc.Scopes,
		)
	case config.TokenProviderModeLocal:
		fallthrough
	default:
		refreshTokenResult, providerErr = s.localTokenProvider.GenerateRefreshToken(
			ctx,
			dc.UserID,
			dc.ClientID,
			dc.Scopes,
		)
	}

	if providerErr != nil {
		log.Printf(
			"[Token] Refresh token generation failed provider=%s: %v",
			s.tokenProviderMode,
			providerErr,
		)
		return nil, nil, fmt.Errorf("refresh token generation failed: %w", providerErr)
	}

	if !refreshTokenResult.Success {
		return nil, nil, fmt.Errorf("refresh token generation unsuccessful")
	}

	// Create access token record
	accessToken := &models.AccessToken{
		ID:            uuid.New().String(),
		Token:         accessTokenResult.TokenString,
		TokenType:     accessTokenResult.TokenType,
		TokenCategory: "access", // Explicitly set token category
		Status:        "active", // Set initial status
		UserID:        dc.UserID,
		ClientID:      dc.ClientID,
		Scopes:        dc.Scopes,
		ExpiresAt:     accessTokenResult.ExpiresAt,
	}

	// Create refresh token record
	refreshToken := &models.AccessToken{
		ID:            uuid.New().String(),
		Token:         refreshTokenResult.TokenString,
		TokenType:     refreshTokenResult.TokenType,
		TokenCategory: "refresh", // Mark as refresh token
		Status:        "active",  // Set initial status
		UserID:        dc.UserID,
		ClientID:      dc.ClientID,
		Scopes:        dc.Scopes,
		ExpiresAt:     refreshTokenResult.ExpiresAt,
	}

	// Save both tokens in transaction
	tx := s.store.DB().Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Create(accessToken).Error; err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to save access token: %w", err)
	}

	if err := tx.Create(refreshToken).Error; err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Delete the used device code
	_ = s.store.DeleteDeviceCodeByID(dc.ID)

	// Log token issuance
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventAccessTokenIssued,
			Severity:     models.SeverityInfo,
			ActorUserID:  accessToken.UserID,
			ResourceType: models.ResourceToken,
			ResourceID:   accessToken.ID,
			Action:       "Access token issued via device code exchange",
			Details: models.AuditDetails{
				"client_id":        accessToken.ClientID,
				"scopes":           accessToken.Scopes,
				"token_provider":   s.tokenProviderMode,
				"refresh_token_id": refreshToken.ID,
			},
			Success: true,
		})

		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventRefreshTokenIssued,
			Severity:     models.SeverityInfo,
			ActorUserID:  refreshToken.UserID,
			ResourceType: models.ResourceToken,
			ResourceID:   refreshToken.ID,
			Action:       "Refresh token issued via device code exchange",
			Details: models.AuditDetails{
				"client_id":       refreshToken.ClientID,
				"scopes":          refreshToken.Scopes,
				"token_provider":  s.tokenProviderMode,
				"access_token_id": accessToken.ID,
			},
			Success: true,
		})
	}

	return accessToken, refreshToken, nil
}

// ValidateToken validates a JWT token using the configured provider
func (s *TokenService) ValidateToken(
	ctx context.Context,
	tokenString string,
) (*token.TokenValidationResult, error) {
	var result *token.TokenValidationResult
	var err error

	switch s.tokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		if s.httpTokenProvider == nil {
			return nil, fmt.Errorf("HTTP token provider not configured")
		}
		result, err = s.httpTokenProvider.ValidateToken(ctx, tokenString)
	case config.TokenProviderModeLocal:
		fallthrough
	default:
		if s.localTokenProvider == nil {
			return nil, fmt.Errorf("local token provider not configured")
		}
		result, err = s.localTokenProvider.ValidateToken(ctx, tokenString)
	}

	if err != nil {
		return nil, err
	}

	// Optional: Check if token exists in database (for revocation check)
	// This adds an extra layer of security
	_, dbErr := s.store.GetAccessToken(tokenString)
	if dbErr != nil {
		// Token was revoked or doesn't exist in our records
		return nil, errors.New("token not found or revoked")
	}

	return result, nil
}

// RevokeToken revokes a token by its JWT string
func (s *TokenService) RevokeToken(tokenString string) error {
	// Get the token from database
	token, err := s.store.GetAccessToken(tokenString)
	if err != nil {
		return errors.New("token not found")
	}

	// Delete the token
	return s.store.RevokeToken(token.ID)
}

// RevokeTokenByID revokes a token by its ID
func (s *TokenService) RevokeTokenByID(ctx context.Context, tokenID, actorUserID string) error {
	// Get token info before revocation
	token, err := s.store.GetAccessTokenByID(tokenID)
	if err != nil {
		return err
	}

	err = s.store.RevokeToken(tokenID)
	if err != nil {
		// Log revocation failure
		if s.auditService != nil {
			s.auditService.Log(ctx, AuditLogEntry{
				EventType:    models.EventTokenRevoked,
				Severity:     models.SeverityError,
				ActorUserID:  actorUserID,
				ResourceType: models.ResourceToken,
				ResourceID:   tokenID,
				Action:       "Token revocation failed",
				Details:      models.AuditDetails{"token_category": token.TokenCategory},
				Success:      false,
				ErrorMessage: err.Error(),
			})
		}
		return err
	}

	// Log token revocation
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventTokenRevoked,
			Severity:     models.SeverityInfo,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceToken,
			ResourceID:   tokenID,
			Action:       "Token revoked",
			Details: models.AuditDetails{
				"token_category": token.TokenCategory,
				"client_id":      token.ClientID,
				"token_user_id":  token.UserID,
			},
			Success: true,
		})
	}

	return nil
}

// GetUserTokens returns all active tokens for a user
func (s *TokenService) GetUserTokens(userID string) ([]models.AccessToken, error) {
	return s.store.GetTokensByUserID(userID)
}

// GetUserTokensWithClient returns all active tokens for a user with client information
func (s *TokenService) GetUserTokensWithClient(userID string) ([]TokenWithClient, error) {
	tokens, err := s.store.GetTokensByUserID(userID)
	if err != nil {
		return nil, err
	}

	if len(tokens) == 0 {
		return []TokenWithClient{}, nil
	}

	// Collect unique client IDs
	clientIDSet := make(map[string]bool)
	for _, token := range tokens {
		clientIDSet[token.ClientID] = true
	}

	clientIDs := make([]string, 0, len(clientIDSet))
	for clientID := range clientIDSet {
		clientIDs = append(clientIDs, clientID)
	}

	// Batch query all clients using WHERE IN
	clientMap, err := s.store.GetClientsByIDs(clientIDs)
	if err != nil {
		return nil, err
	}

	// Combine tokens with client information
	result := make([]TokenWithClient, 0, len(tokens))
	for _, token := range tokens {
		clientName := token.ClientID // Default to ClientID if not found
		if client, ok := clientMap[token.ClientID]; ok && client != nil {
			clientName = client.ClientName
		}

		result = append(result, TokenWithClient{
			AccessToken: token,
			ClientName:  clientName,
		})
	}

	return result, nil
}

// GetUserTokensWithClientPaginated returns paginated tokens for a user with client information
func (s *TokenService) GetUserTokensWithClientPaginated(
	userID string,
	params store.PaginationParams,
) ([]TokenWithClient, store.PaginationResult, error) {
	tokens, pagination, err := s.store.GetTokensByUserIDPaginated(userID, params)
	if err != nil {
		return nil, store.PaginationResult{}, err
	}

	if len(tokens) == 0 {
		return []TokenWithClient{}, pagination, nil
	}

	// Collect unique client IDs
	clientIDSet := make(map[string]bool)
	for _, token := range tokens {
		clientIDSet[token.ClientID] = true
	}

	clientIDs := make([]string, 0, len(clientIDSet))
	for clientID := range clientIDSet {
		clientIDs = append(clientIDs, clientID)
	}

	// Batch query all clients using WHERE IN
	clientMap, err := s.store.GetClientsByIDs(clientIDs)
	if err != nil {
		return nil, store.PaginationResult{}, err
	}

	// Combine tokens with client information
	result := make([]TokenWithClient, 0, len(tokens))
	for _, token := range tokens {
		clientName := token.ClientID // Default to ClientID if not found
		if client, ok := clientMap[token.ClientID]; ok && client != nil {
			clientName = client.ClientName
		}

		result = append(result, TokenWithClient{
			AccessToken: token,
			ClientName:  clientName,
		})
	}

	return result, pagination, nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (s *TokenService) RevokeAllUserTokens(userID string) error {
	return s.store.RevokeTokensByUserID(userID)
}

// RefreshAccessToken generates new access token (and optionally new refresh token in rotation mode)
func (s *TokenService) RefreshAccessToken(
	ctx context.Context,
	refreshTokenString, clientID, requestedScopes string,
) (*models.AccessToken, *models.AccessToken, error) {
	// 1. Get refresh token from database
	refreshToken, err := s.store.GetAccessToken(refreshTokenString)
	if err != nil {
		return nil, nil, token.ErrInvalidRefreshToken
	}

	// 2. Verify token category and status
	if refreshToken.TokenCategory != "refresh" {
		return nil, nil, token.ErrInvalidRefreshToken
	}
	if refreshToken.Status != "active" {
		return nil, nil, token.ErrInvalidRefreshToken // Token disabled or revoked
	}

	// 3. Verify expiration
	if refreshToken.IsExpired() {
		return nil, nil, token.ErrExpiredRefreshToken
	}

	// 4. Verify client_id
	if refreshToken.ClientID != clientID {
		return nil, nil, ErrAccessDenied
	}

	// 5. Verify scope (cannot upgrade)
	if !s.validateScopes(refreshToken.Scopes, requestedScopes) {
		return nil, nil, token.ErrInvalidScope
	}

	// 6. Use provider to generate new tokens (pass rotation config)
	enableRotation := s.config.EnableTokenRotation
	var refreshResult *token.RefreshResult
	var providerErr error

	switch s.tokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		if s.httpTokenProvider == nil {
			return nil, nil, fmt.Errorf("HTTP token provider not configured")
		}
		refreshResult, providerErr = s.httpTokenProvider.RefreshAccessToken(
			ctx,
			refreshTokenString,
			enableRotation,
		)
	case config.TokenProviderModeLocal:
		fallthrough
	default:
		if s.localTokenProvider == nil {
			return nil, nil, fmt.Errorf("local token provider not configured")
		}
		refreshResult, providerErr = s.localTokenProvider.RefreshAccessToken(
			ctx,
			refreshTokenString,
			enableRotation,
		)
	}

	if providerErr != nil {
		log.Printf("[Token] Refresh failed provider=%s: %v", s.tokenProviderMode, providerErr)
		return nil, nil, providerErr
	}

	if !refreshResult.Success {
		return nil, nil, fmt.Errorf("token refresh unsuccessful")
	}

	// 7. Save new tokens in transaction
	tx := s.store.DB().Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 7.1 Create new access token
	newAccessToken := &models.AccessToken{
		ID:            uuid.New().String(),
		Token:         refreshResult.AccessToken.TokenString,
		TokenCategory: "access",
		Status:        "active",
		TokenType:     refreshResult.AccessToken.TokenType,
		UserID:        refreshToken.UserID,
		ClientID:      refreshToken.ClientID,
		Scopes:        refreshToken.Scopes,
		ExpiresAt:     refreshResult.AccessToken.ExpiresAt,
		ParentTokenID: refreshToken.ID, // Token family tracking
	}

	if err := tx.Create(newAccessToken).Error; err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to save new access token: %w", err)
	}

	// 7.2 Handle refresh token based on mode
	var newRefreshToken *models.AccessToken

	if enableRotation && refreshResult.RefreshToken != nil {
		// Rotation mode: create new refresh token, revoke old one
		newRefreshToken = &models.AccessToken{
			ID:            uuid.New().String(),
			Token:         refreshResult.RefreshToken.TokenString,
			TokenCategory: "refresh",
			Status:        "active",
			TokenType:     refreshResult.RefreshToken.TokenType,
			UserID:        refreshToken.UserID,
			ClientID:      refreshToken.ClientID,
			Scopes:        refreshToken.Scopes,
			ExpiresAt:     refreshResult.RefreshToken.ExpiresAt,
			ParentTokenID: refreshToken.ID, // Token family tracking
		}

		if err := tx.Create(newRefreshToken).Error; err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("failed to save new refresh token: %w", err)
		}

		// Revoke old refresh token (soft delete)
		if err := tx.Model(refreshToken).Update("status", "revoked").Error; err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
		}
	} else {
		// Fixed mode: update refresh token's last_used_at
		now := time.Now()
		if err := tx.Model(refreshToken).Update("last_used_at", &now).Error; err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("failed to update refresh token last_used_at: %w", err)
		}
		// Return original refresh token (unchanged)
		newRefreshToken = refreshToken
	}

	if err := tx.Commit().Error; err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Log token refresh
	if s.auditService != nil {
		details := models.AuditDetails{
			"client_id":           newAccessToken.ClientID,
			"scopes":              newAccessToken.Scopes,
			"token_provider":      s.tokenProviderMode,
			"rotation_enabled":    enableRotation,
			"new_access_token_id": newAccessToken.ID,
		}

		if enableRotation && newRefreshToken.ID != refreshToken.ID {
			details["new_refresh_token_id"] = newRefreshToken.ID
			details["old_refresh_token_id"] = refreshToken.ID
		}

		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventTokenRefreshed,
			Severity:     models.SeverityInfo,
			ActorUserID:  newAccessToken.UserID,
			ResourceType: models.ResourceToken,
			ResourceID:   newAccessToken.ID,
			Action:       "Access token refreshed",
			Details:      details,
			Success:      true,
		})
	}

	return newAccessToken, newRefreshToken, nil
}

// validateScopes checks if requested scopes are subset of original scopes
func (s *TokenService) validateScopes(originalScopes, requestedScopes string) bool {
	if requestedScopes == "" {
		return true // No request = inherit original scope
	}

	// Check that requested scopes are subset of original scopes
	originalSet := make(map[string]bool)
	for _, scope := range splitScopes(originalScopes) {
		originalSet[scope] = true
	}

	for _, scope := range splitScopes(requestedScopes) {
		if !originalSet[scope] {
			return false // Requested unauthorized scope
		}
	}

	return true
}

// splitScopes splits space-separated scope string
func splitScopes(scopes string) []string {
	if scopes == "" {
		return []string{}
	}
	return strings.Fields(scopes)
}

// updateTokenStatusWithAudit is a helper function to update token status and log audit events
func (s *TokenService) updateTokenStatusWithAudit(
	ctx context.Context,
	tokenID, actorUserID, newStatus string,
	eventType models.EventType,
	actionSuccess, actionFailed string,
) error {
	// Get token info before updating
	token, err := s.store.GetAccessTokenByID(tokenID)
	if err != nil {
		return err
	}

	err = s.store.UpdateTokenStatus(tokenID, newStatus)
	if err != nil {
		// Log failure
		if s.auditService != nil {
			s.auditService.Log(ctx, AuditLogEntry{
				EventType:    eventType,
				Severity:     models.SeverityError,
				ActorUserID:  actorUserID,
				ResourceType: models.ResourceToken,
				ResourceID:   tokenID,
				Action:       actionFailed,
				Details:      models.AuditDetails{"token_category": token.TokenCategory},
				Success:      false,
				ErrorMessage: err.Error(),
			})
		}
		return err
	}

	// Log success
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    eventType,
			Severity:     models.SeverityInfo,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceToken,
			ResourceID:   tokenID,
			Action:       actionSuccess,
			Details: models.AuditDetails{
				"token_category": token.TokenCategory,
				"client_id":      token.ClientID,
				"token_user_id":  token.UserID,
			},
			Success: true,
		})
	}

	return nil
}

// DisableToken disables a token (can be re-enabled)
func (s *TokenService) DisableToken(ctx context.Context, tokenID, actorUserID string) error {
	return s.updateTokenStatusWithAudit(
		ctx,
		tokenID,
		actorUserID,
		"disabled",
		models.EventTokenDisabled,
		"Token disabled",
		"Token disable failed",
	)
}

// EnableToken re-enables a disabled token
func (s *TokenService) EnableToken(ctx context.Context, tokenID, actorUserID string) error {
	return s.updateTokenStatusWithAudit(
		ctx,
		tokenID,
		actorUserID,
		"active",
		models.EventTokenEnabled,
		"Token enabled",
		"Token enable failed",
	)
}

// RevokeTokenByStatus permanently revokes a token (uses status update, not deletion)
func (s *TokenService) RevokeTokenByStatus(tokenID string) error {
	return s.store.UpdateTokenStatus(tokenID, "revoked")
}

// GetActiveRefreshTokens gets all active refresh tokens for a user
func (s *TokenService) GetActiveRefreshTokens(userID string) ([]models.AccessToken, error) {
	return s.store.GetTokensByCategoryAndStatus(userID, "refresh", "active")
}
