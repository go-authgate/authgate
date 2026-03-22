package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
)

// revokeTokenFamilyWithAudit revokes all active tokens in a token family when refresh token
// reuse is detected during rotation mode. This prevents stolen token abuse by invalidating
// all active tokens derived from the same parent (RFC 6819 §4.14.2).
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

// GetActiveRefreshTokens gets all active refresh tokens for a user
func (s *TokenService) GetActiveRefreshTokens(userID string) ([]models.AccessToken, error) {
	return s.store.GetTokensByCategoryAndStatus(
		userID,
		models.TokenCategoryRefresh,
		models.TokenStatusActive,
	)
}
