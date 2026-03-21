package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
	"gorm.io/gorm"
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
	ErrTokenCannotDisable   = errors.New(
		"token cannot be disabled: only active tokens can be disabled",
	)
	ErrTokenCannotEnable = errors.New(
		"token cannot be enabled: only disabled tokens can be re-enabled",
	)

	// Client Credentials Flow errors (RFC 6749 §4.4)
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrClientNotConfidential    = errors.New(
		"client_credentials grant requires a confidential client",
	)
	ErrClientCredentialsFlowDisabled = errors.New(
		"client_credentials flow is not enabled for this client",
	)
)

type TokenService struct {
	store         core.Store
	config        *config.Config
	deviceService *DeviceService
	tokenProvider core.TokenProvider
	auditService  *AuditService
	metrics       core.Recorder
}

func NewTokenService(
	s core.Store,
	cfg *config.Config,
	ds *DeviceService,
	provider core.TokenProvider,
	auditService *AuditService,
	m core.Recorder,
) *TokenService {
	return &TokenService{
		store:         s,
		config:        cfg,
		deviceService: ds,
		tokenProvider: provider,
		auditService:  auditService,
		metrics:       m,
	}
}

// tokenPairParams holds the inputs for creating an access + refresh token pair.
type tokenPairParams struct {
	UserID          string
	ClientID        string
	Scopes          string
	AuthorizationID *uint // nil when not linked to a UserAuthorization (e.g. device flow)
}

// generateAndPersistTokenPair generates access and refresh tokens via the
// configured provider, builds database records, and persists them atomically.
func (s *TokenService) generateAndPersistTokenPair(
	ctx context.Context,
	p tokenPairParams,
) (*models.AccessToken, *models.AccessToken, error) {
	// Generate tokens via provider
	accessResult, err := s.tokenProvider.GenerateToken(ctx, p.UserID, p.ClientID, p.Scopes)
	if err != nil {
		log.Printf(
			"[Token] Access token generation failed provider=%s: %v",
			s.tokenProvider.Name(),
			err,
		)
		return nil, nil, fmt.Errorf("token generation failed: %w", err)
	}
	refreshResult, err := s.tokenProvider.GenerateRefreshToken(ctx, p.UserID, p.ClientID, p.Scopes)
	if err != nil {
		log.Printf(
			"[Token] Refresh token generation failed provider=%s: %v",
			s.tokenProvider.Name(),
			err,
		)
		return nil, nil, fmt.Errorf("refresh token generation failed: %w", err)
	}

	// Build token records
	accessToken := &models.AccessToken{
		ID:              uuid.New().String(),
		TokenHash:       util.SHA256Hex(accessResult.TokenString),
		RawToken:        accessResult.TokenString,
		TokenType:       accessResult.TokenType,
		TokenCategory:   models.TokenCategoryAccess,
		Status:          models.TokenStatusActive,
		UserID:          p.UserID,
		ClientID:        p.ClientID,
		Scopes:          p.Scopes,
		ExpiresAt:       accessResult.ExpiresAt,
		AuthorizationID: p.AuthorizationID,
	}

	refreshTokenID := uuid.New().String()
	refreshToken := &models.AccessToken{
		ID:              refreshTokenID,
		TokenHash:       util.SHA256Hex(refreshResult.TokenString),
		RawToken:        refreshResult.TokenString,
		TokenType:       refreshResult.TokenType,
		TokenCategory:   models.TokenCategoryRefresh,
		Status:          models.TokenStatusActive,
		UserID:          p.UserID,
		ClientID:        p.ClientID,
		Scopes:          p.Scopes,
		ExpiresAt:       refreshResult.ExpiresAt,
		AuthorizationID: p.AuthorizationID,
	}

	// In rotation mode, set TokenFamilyID to the refresh token's own ID (family root)
	if s.config.EnableTokenRotation {
		refreshToken.TokenFamilyID = refreshTokenID
		accessToken.TokenFamilyID = refreshTokenID
	}

	// Persist both tokens atomically
	if err := s.store.RunInTransaction(func(tx core.Store) error {
		if err := tx.CreateAccessToken(accessToken); err != nil {
			return fmt.Errorf("failed to save access token: %w", err)
		}
		if err := tx.CreateAccessToken(refreshToken); err != nil {
			return fmt.Errorf("failed to save refresh token: %w", err)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

// ExchangeDeviceCode exchanges an authorized device code for access and refresh tokens
func (s *TokenService) ExchangeDeviceCode(
	ctx context.Context,
	deviceCode, clientID string,
) (*models.AccessToken, *models.AccessToken, error) {
	dc, err := s.deviceService.GetDeviceCode(deviceCode)
	if err != nil {
		result := "invalid"
		if errors.Is(err, ErrDeviceCodeExpired) {
			result = "expired"
		}
		s.metrics.RecordOAuthDeviceCodeValidation(result)
		if errors.Is(err, ErrDeviceCodeExpired) {
			return nil, nil, ErrExpiredToken
		}
		return nil, nil, ErrAccessDenied
	}

	// Check if client matches
	if dc.ClientID != clientID {
		s.metrics.RecordOAuthDeviceCodeValidation("invalid")
		return nil, nil, ErrAccessDenied
	}

	// Check if client is active
	client, err := s.store.GetClient(clientID)
	if err != nil {
		s.metrics.RecordOAuthDeviceCodeValidation("invalid")
		return nil, nil, ErrAccessDenied
	}
	if !client.IsActive() {
		s.metrics.RecordOAuthDeviceCodeValidation("invalid")
		return nil, nil, ErrAccessDenied
	}

	// Check if authorized
	if !dc.Authorized {
		s.metrics.RecordOAuthDeviceCodeValidation("pending")
		return nil, nil, ErrAuthorizationPending
	}

	// Record successful validation
	s.metrics.RecordOAuthDeviceCodeValidation("success")

	// Generate and persist token pair
	start := time.Now()
	accessToken, refreshToken, err := s.generateAndPersistTokenPair(ctx, tokenPairParams{
		UserID:   dc.UserID,
		ClientID: dc.ClientID,
		Scopes:   dc.Scopes,
	})
	if err != nil {
		return nil, nil, err
	}

	// Record token issuance metrics
	duration := time.Since(start)
	providerName := s.tokenProvider.Name()
	s.metrics.RecordTokenIssued("access", "device_code", duration, providerName)
	s.metrics.RecordTokenIssued("refresh", "device_code", duration, providerName)

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
				"token_provider":   providerName,
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
				"token_provider":  providerName,
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
) (*token.ValidationResult, error) {
	result, err := s.tokenProvider.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// Check token exists in database and validate its state (revocation, expiry, category)
	tok, err := s.store.GetAccessTokenByHash(util.SHA256Hex(tokenString))
	if err != nil {
		return nil, errors.New("token not found or revoked")
	}
	if !tok.IsAccessToken() {
		return nil, errors.New("token is not an access token")
	}
	if !tok.IsActive() {
		return nil, errors.New("token not found or revoked")
	}
	if tok.IsExpired() {
		return nil, errors.New("token has expired")
	}

	return result, nil
}

// IntrospectToken looks up a token by its raw string and returns the database record
// along with its active status. Unlike ValidateToken, this method does NOT require
// JWT signature validation — it is designed for RFC 7662 introspection where the
// authorization server is the token issuer and can rely on its own database state.
// Returns (token, true) for active tokens, (token, false) for inactive/expired tokens,
// and (nil, false) if the token does not exist.
func (s *TokenService) IntrospectToken(
	ctx context.Context,
	tokenString, callerClientID string,
) (*models.AccessToken, bool) {
	tok, err := s.store.GetAccessTokenByHash(util.SHA256Hex(tokenString))
	if err != nil {
		return nil, false
	}

	active := tok.IsActive() && !tok.IsExpired()

	// Audit log the introspection event
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventTokenIntrospected,
			Severity:     models.SeverityInfo,
			ActorUserID:  "client:" + callerClientID,
			ResourceType: models.ResourceToken,
			ResourceID:   tok.ID,
			Action:       "Token introspected",
			Details: models.AuditDetails{
				"caller_client_id": callerClientID,
				"token_client_id":  tok.ClientID,
				"token_user_id":    tok.UserID,
				"token_category":   tok.TokenCategory,
				"active":           active,
			},
			Success: true,
		})
	}

	return tok, active
}

// RevokeToken revokes a token by its JWT string
func (s *TokenService) RevokeToken(tokenString string) error {
	// Get the token from database
	tok, err := s.store.GetAccessTokenByHash(util.SHA256Hex(tokenString))
	if err != nil {
		return errors.New("token not found")
	}

	// Delete the token
	return s.store.RevokeToken(tok.ID)
}

// RevokeTokenByID revokes a token by its ID
func (s *TokenService) RevokeTokenByID(ctx context.Context, tokenID, actorUserID string) error {
	// Get token info before revocation
	tok, err := s.store.GetAccessTokenByID(tokenID)
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
				Details:      models.AuditDetails{"token_category": tok.TokenCategory},
				Success:      false,
				ErrorMessage: err.Error(),
			})
		}
		return err
	}

	// Record revocation
	s.metrics.RecordTokenRevoked(tok.TokenCategory, "user_request")

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
				"token_category": tok.TokenCategory,
				"client_id":      tok.ClientID,
				"token_user_id":  tok.UserID,
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

// IsTokenOwnedByUser returns true if the token with the given ID belongs to the given user.
// A missing token is treated the same as an unowned token: returns (false, nil).
func (s *TokenService) IsTokenOwnedByUser(tokenID, userID string) (bool, error) {
	tok, err := s.store.GetAccessTokenByID(tokenID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return tok.UserID == userID, nil
}

// enrichTokensWithClients batch-fetches client names and joins them onto a token slice.
func (s *TokenService) enrichTokensWithClients(
	tokens []models.AccessToken,
) ([]TokenWithClient, error) {
	clientIDs := util.UniqueKeys(tokens, func(t models.AccessToken) string { return t.ClientID })
	clientMap, err := s.store.GetClientsByIDs(clientIDs)
	if err != nil {
		return nil, err
	}
	result := make([]TokenWithClient, 0, len(tokens))
	for _, tok := range tokens {
		clientName := tok.ClientID // Default to ClientID if not found
		if client, ok := clientMap[tok.ClientID]; ok && client != nil {
			clientName = client.ClientName
		}
		result = append(result, TokenWithClient{AccessToken: tok, ClientName: clientName})
	}
	return result, nil
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
	return s.enrichTokensWithClients(tokens)
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
	result, err := s.enrichTokensWithClients(tokens)
	if err != nil {
		return nil, store.PaginationResult{}, err
	}
	return result, pagination, nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (s *TokenService) RevokeAllUserTokens(userID string) error {
	return s.store.RevokeTokensByUserID(userID)
}

// revokeTokenFamilyWithAudit revokes all tokens in a token family when refresh token
// reuse is detected during rotation mode. This prevents stolen token abuse by invalidating
// all tokens derived from the same parent (RFC 6819 §4.14.2).
func (s *TokenService) revokeTokenFamilyWithAudit(
	ctx context.Context, reusedToken *models.AccessToken,
) {
	familyID := reusedToken.TokenFamilyID
	if familyID == "" {
		// Fallback for tokens created before TokenFamilyID was introduced
		familyID = reusedToken.ParentTokenID
		if familyID == "" {
			familyID = reusedToken.ID
		}
	}

	revokedCount, err := s.store.RevokeTokenFamily(familyID)
	if err != nil {
		log.Printf("[Token] Failed to revoke token family %s: %v", familyID, err)
		return
	}

	// Record family revocation event
	if revokedCount > 0 {
		s.metrics.RecordTokenRevoked("family", "replay_detection")
	}

	// Audit log — CRITICAL severity because this indicates potential token theft
	if s.auditService != nil {
		_ = s.auditService.LogSync(ctx, AuditLogEntry{
			EventType:    models.EventSuspiciousActivity,
			Severity:     models.SeverityCritical,
			ActorUserID:  reusedToken.UserID,
			ResourceType: models.ResourceToken,
			ResourceID:   reusedToken.ID,
			Action:       "Refresh token reuse detected — token family revoked",
			Details: models.AuditDetails{
				"family_id":       familyID,
				"reused_token_id": reusedToken.ID,
				"client_id":       reusedToken.ClientID,
				"tokens_revoked":  revokedCount,
			},
			Success: true,
		})
	}
}

// RefreshAccessToken generates new access token (and optionally new refresh token in rotation mode)
func (s *TokenService) RefreshAccessToken(
	ctx context.Context,
	refreshTokenString, clientID, requestedScopes string,
) (*models.AccessToken, *models.AccessToken, error) {
	// 1. Get refresh token from database
	refreshToken, err := s.store.GetAccessTokenByHash(util.SHA256Hex(refreshTokenString))
	if err != nil {
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, token.ErrInvalidRefreshToken
	}

	// 2. Verify token category and status
	if !refreshToken.IsRefreshToken() {
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, token.ErrInvalidRefreshToken
	}
	if !refreshToken.IsActive() {
		// In rotation mode, a non-active refresh token being reused indicates
		// potential token theft (RFC 6819 §4.14.2). Revoke the entire token family.
		if s.config.EnableTokenRotation && (refreshToken.IsRevoked() || refreshToken.IsDisabled()) {
			s.revokeTokenFamilyWithAudit(ctx, refreshToken)
		}
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, token.ErrInvalidRefreshToken
	}

	// 3. Verify expiration
	if refreshToken.IsExpired() {
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, token.ErrExpiredRefreshToken
	}

	// 4. Verify client_id
	if refreshToken.ClientID != clientID {
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, ErrAccessDenied
	}

	// 5. Verify scope (cannot upgrade)
	if !util.IsScopeSubset(refreshToken.Scopes, requestedScopes) {
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, token.ErrInvalidScope
	}

	// 6. Use provider to generate new tokens
	refreshResult, providerErr := s.tokenProvider.RefreshAccessToken(
		ctx,
		refreshTokenString,
	)
	if providerErr != nil {
		log.Printf("[Token] Refresh failed provider=%s: %v", s.tokenProvider.Name(), providerErr)
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, providerErr
	}

	// 7. Save new tokens in transaction
	// 7.1 Create new access token
	newAccessToken := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(refreshResult.AccessToken.TokenString),
		RawToken:      refreshResult.AccessToken.TokenString,
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		TokenType:     refreshResult.AccessToken.TokenType,
		UserID:        refreshToken.UserID,
		ClientID:      refreshToken.ClientID,
		Scopes:        refreshToken.Scopes,
		ExpiresAt:     refreshResult.AccessToken.ExpiresAt,
		ParentTokenID: refreshToken.ID,
		TokenFamilyID: refreshToken.TokenFamilyID, // Inherit family ID
	}

	// 7.2 Handle refresh token based on mode
	var newRefreshToken *models.AccessToken

	if s.config.EnableTokenRotation && refreshResult.RefreshToken != nil {
		// Rotation mode: create new refresh token, revoke old one
		newRefreshToken = &models.AccessToken{
			ID:            uuid.New().String(),
			TokenHash:     util.SHA256Hex(refreshResult.RefreshToken.TokenString),
			RawToken:      refreshResult.RefreshToken.TokenString,
			TokenCategory: models.TokenCategoryRefresh,
			Status:        models.TokenStatusActive,
			TokenType:     refreshResult.RefreshToken.TokenType,
			UserID:        refreshToken.UserID,
			ClientID:      refreshToken.ClientID,
			Scopes:        refreshToken.Scopes,
			ExpiresAt:     refreshResult.RefreshToken.ExpiresAt,
			ParentTokenID: refreshToken.ID,
			TokenFamilyID: refreshToken.TokenFamilyID, // Inherit family ID
		}
	}

	if err := s.store.RunInTransaction(func(tx core.Store) error {
		if err := tx.CreateAccessToken(newAccessToken); err != nil {
			return fmt.Errorf("failed to save new access token: %w", err)
		}

		if s.config.EnableTokenRotation && newRefreshToken != nil {
			if err := tx.CreateAccessToken(newRefreshToken); err != nil {
				return fmt.Errorf("failed to save new refresh token: %w", err)
			}
			// Revoke old refresh token
			if err := tx.UpdateTokenStatus(refreshToken.ID, models.TokenStatusRevoked); err != nil {
				return fmt.Errorf("failed to revoke old refresh token: %w", err)
			}
		} else {
			// Fixed mode: update refresh token's last_used_at
			if err := tx.UpdateTokenLastUsedAt(refreshToken.ID, time.Now()); err != nil {
				return fmt.Errorf("failed to update refresh token last_used_at: %w", err)
			}
		}
		return nil
	}); err != nil {
		s.metrics.RecordTokenRefresh(false)
		return nil, nil, err
	}

	// Fixed mode: return original refresh token with RawToken restored
	if newRefreshToken == nil {
		refreshToken.RawToken = refreshTokenString
		newRefreshToken = refreshToken
	}

	// Record successful refresh
	s.metrics.RecordTokenRefresh(true)

	// Log token refresh
	if s.auditService != nil {
		providerName := s.tokenProvider.Name()
		rotated := s.config.EnableTokenRotation && refreshResult.RefreshToken != nil
		details := models.AuditDetails{
			"client_id":           newAccessToken.ClientID,
			"scopes":              newAccessToken.Scopes,
			"token_provider":      providerName,
			"rotation_enabled":    rotated,
			"new_access_token_id": newAccessToken.ID,
		}

		if rotated && newRefreshToken.ID != refreshToken.ID {
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

// IssueClientCredentialsToken issues an access token for the client_credentials grant
// (RFC 6749 §4.4). Only confidential clients with EnableClientCredentialsFlow=true may use
// this flow. No refresh token is issued (per RFC 6749 §4.4.3).
//
// The resulting token carries a synthetic machine identity in UserID: "client:<clientID>".
// This distinguishes M2M tokens from user-delegated tokens in all downstream lookups.
func (s *TokenService) IssueClientCredentialsToken(
	ctx context.Context,
	clientID, clientSecret, requestedScopes string,
) (*models.AccessToken, error) {
	// 1. Look up client and verify it is active
	client, err := s.store.GetClient(clientID)
	if err != nil || !client.IsActive() {
		return nil, ErrInvalidClientCredentials
	}

	// 2. Only confidential clients may use this flow
	if core.ClientType(client.ClientType) != core.ClientTypeConfidential {
		return nil, ErrClientNotConfidential
	}

	// 3. Flow must be explicitly enabled on the client
	if !client.EnableClientCredentialsFlow {
		return nil, ErrClientCredentialsFlowDisabled
	}

	// 4. Authenticate the client via its secret
	if !client.ValidateClientSecret([]byte(clientSecret)) {
		return nil, ErrInvalidClientCredentials
	}

	// 5. Resolve effective scopes
	effectiveScopes := requestedScopes
	if effectiveScopes == "" {
		// Default: grant all scopes the client is registered for
		effectiveScopes = client.Scopes
	} else {
		// Reject user-centric OIDC scopes — there is no user in this flow
		for scope := range strings.FieldsSeq(effectiveScopes) {
			if scope == "openid" || scope == "offline_access" {
				return nil, token.ErrInvalidScope
			}
		}
		// Requested scopes must be a strict subset of the client's registered scopes
		if !util.IsScopeSubset(client.Scopes, effectiveScopes) {
			return nil, token.ErrInvalidScope
		}
	}

	// 6. Generate access token — synthetic machine identity carries no real user
	start := time.Now()
	machineUserID := "client:" + clientID

	accessTokenResult, providerErr := s.tokenProvider.GenerateClientCredentialsToken(
		ctx,
		machineUserID,
		clientID,
		effectiveScopes,
	)
	if providerErr != nil {
		log.Printf(
			"[Token] Client credentials token generation failed provider=%s: %v",
			s.tokenProvider.Name(),
			providerErr,
		)
		return nil, fmt.Errorf("token generation failed: %w", providerErr)
	}
	// 7. Persist the token record (no AuthorizationID — no user consent)
	accessToken := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(accessTokenResult.TokenString),
		RawToken:      accessTokenResult.TokenString,
		TokenType:     accessTokenResult.TokenType,
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        machineUserID,
		ClientID:      clientID,
		Scopes:        effectiveScopes,
		ExpiresAt:     accessTokenResult.ExpiresAt,
	}

	if err := s.store.CreateAccessToken(accessToken); err != nil {
		return nil, fmt.Errorf("failed to save access token: %w", err)
	}

	// 8. Metrics
	providerName := s.tokenProvider.Name()
	duration := time.Since(start)
	s.metrics.RecordTokenIssued("access", "client_credentials", duration, providerName)

	// 9. Audit log
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientCredentialsTokenIssued,
			Severity:     models.SeverityInfo,
			ActorUserID:  machineUserID,
			ResourceType: models.ResourceToken,
			ResourceID:   accessToken.ID,
			Action:       "Access token issued via client credentials grant",
			Details: models.AuditDetails{
				"client_id":      clientID,
				"scopes":         effectiveScopes,
				"token_provider": providerName,
			},
			Success: true,
		})
	}

	return accessToken, nil
}

// GetUserByID returns a user by their ID.
func (s *TokenService) GetUserByID(userID string) (*models.User, error) {
	return s.store.GetUserByID(userID)
}

// AuthenticateClient verifies client credentials (client_id + client_secret).
// Returns nil on success, or an error if the client is not found or the secret is invalid.
func (s *TokenService) AuthenticateClient(clientID, clientSecret string) error {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrInvalidClientCredentials
	}
	if !client.ValidateClientSecret([]byte(clientSecret)) {
		return ErrInvalidClientCredentials
	}
	return nil
}

// updateTokenStatusWithAudit is a helper function to update token status and log audit events
func (s *TokenService) updateTokenStatusWithAudit(
	ctx context.Context,
	tokenID, actorUserID, newStatus string,
	eventType models.EventType,
	actionSuccess, actionFailed string,
) error {
	// Get token info before updating
	tok, err := s.store.GetAccessTokenByID(tokenID)
	if err != nil {
		return err
	}

	// Validate state transition
	switch newStatus {
	case models.TokenStatusDisabled:
		// Only active tokens can be disabled
		if !tok.IsActive() {
			return ErrTokenCannotDisable
		}
	case models.TokenStatusActive:
		// Re-enabling is only allowed from disabled state; revoked tokens must not be re-activated
		if !tok.IsDisabled() {
			return ErrTokenCannotEnable
		}
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
				Details:      models.AuditDetails{"token_category": tok.TokenCategory},
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
				"token_category": tok.TokenCategory,
				"client_id":      tok.ClientID,
				"token_user_id":  tok.UserID,
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
		models.TokenStatusDisabled,
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
		models.TokenStatusActive,
		models.EventTokenEnabled,
		"Token enabled",
		"Token enable failed",
	)
}

// RevokeTokenByStatus permanently revokes a token (uses status update, not deletion)
func (s *TokenService) RevokeTokenByStatus(tokenID string) error {
	return s.store.UpdateTokenStatus(tokenID, models.TokenStatusRevoked)
}

// GetActiveRefreshTokens gets all active refresh tokens for a user
func (s *TokenService) GetActiveRefreshTokens(userID string) ([]models.AccessToken, error) {
	return s.store.GetTokensByCategoryAndStatus(
		userID,
		models.TokenCategoryRefresh,
		models.TokenStatusActive,
	)
}

// ExchangeAuthorizationCode issues an access token, a refresh token, and (when the openid scope
// was granted) an OIDC ID Token for an already-validated authorization code.
// The AuthorizationCode record must have been validated and marked as used by
// AuthorizationService.ExchangeCode before calling this method.
// Returns: accessToken, refreshToken, idToken (empty string when openid not requested), error.
func (s *TokenService) ExchangeAuthorizationCode(
	ctx context.Context,
	authCode *models.AuthorizationCode,
	authorizationID *uint,
) (*models.AccessToken, *models.AccessToken, string, error) {
	start := time.Now()
	providerName := s.tokenProvider.Name()

	// Generate and persist token pair (linked to UserAuthorization for cascade-revoke)
	accessToken, refreshToken, err := s.generateAndPersistTokenPair(ctx, tokenPairParams{
		UserID:          authCode.UserID,
		ClientID:        authCode.ClientID,
		Scopes:          authCode.Scopes,
		AuthorizationID: authorizationID,
	})
	if err != nil {
		return nil, nil, "", err
	}

	// Generate OIDC ID Token when openid scope was granted (OIDC Core 1.0 §3.1.3.3).
	// ID tokens are not stored in the database; they are short-lived and non-revocable.
	// ID token generation is only supported when the provider implements IDTokenProvider.
	var idToken string
	if idp, ok := s.tokenProvider.(core.IDTokenProvider); ok {
		scopeSet := util.ScopeSet(authCode.Scopes)
		if scopeSet["openid"] {
			params := token.IDTokenParams{
				Issuer:   strings.TrimRight(s.config.BaseURL, "/"),
				Subject:  authCode.UserID,
				Audience: authCode.ClientID,
				AuthTime: authCode.CreatedAt,
				Nonce:    authCode.Nonce,
				AtHash:   token.ComputeAtHash(accessToken.RawToken),
			}

			// Fetch user profile for scope-gated claims
			if user, err := s.store.GetUserByID(authCode.UserID); err == nil {
				if scopeSet["profile"] {
					params.Name = user.FullName
					params.PreferredUsername = user.Username
					params.Picture = user.AvatarURL
					updatedAt := user.UpdatedAt
					params.UpdatedAt = &updatedAt
				}
				if scopeSet["email"] {
					params.Email = user.Email
					params.EmailVerified = false // AuthGate does not verify email addresses
				}
			} else if scopeSet["profile"] || scopeSet["email"] {
				log.Printf(
					"[Token] ID token: failed to fetch user profile for user_id=%s, profile/email claims will be omitted: %v",
					authCode.UserID,
					err,
				)
			}

			if generated, err := idp.GenerateIDToken(params); err == nil {
				idToken = generated
				if s.auditService != nil {
					s.auditService.Log(ctx, AuditLogEntry{
						EventType:    models.EventIDTokenIssued,
						Severity:     models.SeverityInfo,
						ActorUserID:  authCode.UserID,
						ResourceType: models.ResourceToken,
						ResourceID:   accessToken.ID,
						Action:       "ID token issued via authorization code exchange",
						Details: models.AuditDetails{
							"client_id":       authCode.ClientID,
							"scopes":          authCode.Scopes,
							"token_provider":  providerName,
							"access_token_id": accessToken.ID,
						},
						Success: true,
					})
				}
			} else {
				log.Printf("[Token] ID token generation failed: %v", err)
			}
		}
	}

	// Metrics
	duration := time.Since(start)
	s.metrics.RecordTokenIssued("access", "authorization_code", duration, providerName)
	s.metrics.RecordTokenIssued("refresh", "authorization_code", duration, providerName)

	// Audit
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventAccessTokenIssued,
			Severity:     models.SeverityInfo,
			ActorUserID:  accessToken.UserID,
			ResourceType: models.ResourceToken,
			ResourceID:   accessToken.ID,
			Action:       "Access token issued via authorization code exchange",
			Details: models.AuditDetails{
				"client_id":        accessToken.ClientID,
				"scopes":           accessToken.Scopes,
				"token_provider":   providerName,
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
			Action:       "Refresh token issued via authorization code exchange",
			Details: models.AuditDetails{
				"client_id":       refreshToken.ClientID,
				"scopes":          refreshToken.Scopes,
				"token_provider":  providerName,
				"access_token_id": accessToken.ID,
			},
			Success: true,
		})
	}

	return accessToken, refreshToken, idToken, nil
}
