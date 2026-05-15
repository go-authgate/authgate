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

	// Collect hashes before revocation for cache invalidation
	hashesToInvalidate, err := s.store.GetActiveTokenHashesByFamilyID(familyID)
	if err != nil {
		log.Printf(
			"[TokenCache] failed to collect family hashes for invalidation family=%s: %v",
			familyID, err,
		)
	}

	revokedCount, err := s.store.RevokeTokenFamily(familyID)
	if err != nil {
		log.Printf("[Token] Failed to revoke token family %s: %v", familyID, err)
		return
	}

	// Invalidate cached tokens in the revoked family
	s.invalidateTokenCacheByHashes(ctx, hashesToInvalidate)

	// Record family revocation event
	if revokedCount > 0 {
		s.metrics.RecordTokenRevoked("family", "replay_detection")
	}

	// Audit log — CRITICAL severity because this indicates potential token theft.
	// ActorUsername is auto-resolved by buildAuditLog.
	_ = s.auditService.LogSync(ctx, core.AuditLogEntry{
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

// RefreshAccessToken generates new access token (and optionally new refresh token in rotation mode).
// callerExtra (optional) is freshly applied to the new token(s) and merged
// with the client's system-managed claims (project, service_account); reserved
// keys must already have been rejected by the handler. Custom claims are NOT
// persisted server-side — callers must re-supply on every refresh request to
// retain them.
//
// requestedResource (optional, RFC 8707 §2.2) narrows the new access token's
// `aud` claim — it MUST be a subset of the original grant's resources. When
// empty, the audience persisted at issuance is reused (no narrowing, no
// widening). A non-subset value returns ErrInvalidTarget.
//
// The rotated refresh token's JWT `aud` is unaffected by this parameter:
// refresh JWTs are signed with nil audience (falling back to the static
// JWTAudience config) so they cannot be silently accepted as access tokens
// by a resource server that only checks signature/iss/exp/aud. The new
// refresh-token row's persisted Resource column keeps the original grant's
// resource set for future §2.2 subset checks.
func (s *TokenService) RefreshAccessToken(
	ctx context.Context,
	refreshTokenString, clientID, requestedScopes string,
	callerExtra map[string]any,
	requestedResource []string,
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

	// 5b. Resolve effective resource per RFC 8707 §2.2: the refresh request
	// MAY narrow the audience but MUST NOT widen it. When the caller omits
	// `resource`, reuse the original grant's bound resources unchanged.
	originalResource := []string(refreshToken.Resource)
	effectiveResource := originalResource
	if len(requestedResource) > 0 {
		if !util.IsStringSliceSubset(originalResource, requestedResource) {
			s.metrics.RecordTokenRefresh(false)
			return nil, nil, ErrInvalidTarget
		}
		effectiveResource = requestedResource
	}

	// 6. Use provider to generate new tokens.
	// Re-resolve TTLs and extra claims at refresh time so admin changes to the
	// client's TokenProfile / Project / ServiceAccount take effect on the next
	// refresh instead of being pinned to issuance-time values. One client
	// fetch serves both: refresh is a hot path, so we don't repeat the lookup.
	var (
		accessTTL, refreshTTL time.Duration
		client                *models.OAuthApplication
	)
	if s.clientService != nil {
		c, err := s.clientService.GetClient(ctx, refreshToken.ClientID)
		if err != nil {
			// Tolerate transient lookup failures — refresh proceeds with provider
			// defaults rather than failing the user's request — but log so the
			// silent loss of TokenProfile TTLs / project / service_account claims
			// is at least diagnosable.
			log.Printf(
				"[Token] Refresh client lookup failed, falling back to defaults client_id=%s: %v",
				refreshToken.ClientID, err,
			)
		} else {
			accessTTL, refreshTTL = s.ttlForClient(c)
			client = c
		}
	}
	extraClaims := s.composeIssuanceClaims(client, refreshToken.UserID, callerExtra)
	// Access token's `aud` = effectiveResource (possibly narrowed).
	// Refresh token's `aud` override = nil → provider falls back to the
	// static JWTAudience config; the refresh JWT must not carry the
	// per-request RFC 8707 resource because it's presented to the AS, not
	// the RS. The persisted Resource column (set below) tracks the original
	// grant for §2.2 subset checks on future refreshes.
	refreshResult, providerErr := s.tokenProvider.RefreshAccessToken(
		ctx,
		refreshTokenString,
		accessTTL,
		refreshTTL,
		extraClaims,
		effectiveResource,
		nil,
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
		Resource:      models.StringArray(effectiveResource),
	}

	// 7.2 Handle refresh token based on mode
	var newRefreshToken *models.AccessToken

	if s.config.EnableTokenRotation && refreshResult.RefreshToken != nil {
		// Rotation mode: create new refresh token, revoke old one. The new
		// refresh token's Resource is the original grant (not the narrowed
		// access-token audience) — RFC 8707 §2.2 subset checks on future
		// refreshes compare against this row, so narrowing must always be
		// relative to the original grant.
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
			Resource:      models.StringArray(originalResource),
		}
	}

	rotated := s.config.EnableTokenRotation && newRefreshToken != nil
	if err := s.store.RunInTransaction(func(tx core.Store) error {
		if err := tx.CreateAccessToken(newAccessToken); err != nil {
			return fmt.Errorf("failed to save new access token: %w", err)
		}

		if rotated {
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

	// Invalidate cache after transaction commits successfully
	if rotated {
		s.invalidateTokenCache(ctx, refreshToken.TokenHash)
	}

	// Fixed mode: return original refresh token with RawToken restored
	if newRefreshToken == nil {
		refreshToken.RawToken = refreshTokenString
		newRefreshToken = refreshToken
	}

	// Record successful refresh
	s.metrics.RecordTokenRefresh(true)

	// Log token refresh — ActorUsername is auto-resolved by buildAuditLog.
	providerName := s.tokenProvider.Name()
	details := models.AuditDetails{
		"client_id":           newAccessToken.ClientID,
		"scopes":              newAccessToken.Scopes,
		"token_provider":      providerName,
		"rotation_enabled":    s.config.EnableTokenRotation,
		"new_access_token_id": newAccessToken.ID,
	}

	if rotated && newRefreshToken.ID != refreshToken.ID {
		details["new_refresh_token_id"] = newRefreshToken.ID
		details["old_refresh_token_id"] = refreshToken.ID
	}

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventTokenRefreshed,
		Severity:     models.SeverityInfo,
		ActorUserID:  newAccessToken.UserID,
		ResourceType: models.ResourceToken,
		ResourceID:   newAccessToken.ID,
		Action:       "Access token refreshed",
		Details:      details,
		Success:      true,
	})

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
