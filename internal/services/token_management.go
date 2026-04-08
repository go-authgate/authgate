package services

import (
	"context"
	"errors"
	"log"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"
)

// Token status management operations (revoke, disable, enable)

// RevokeToken revokes a token by its JWT string
func (s *TokenService) RevokeToken(tokenString string) error {
	hash := util.SHA256Hex(tokenString)

	// Get the token from database
	tok, err := s.store.GetAccessTokenByHash(hash)
	if err != nil {
		return errors.New("token not found")
	}

	// Delete the token
	if err := s.store.RevokeToken(tok.ID); err != nil {
		return err
	}

	s.invalidateTokenCache(context.Background(), hash)

	return nil
}

// RevokeTokenByID revokes a token by its ID
func (s *TokenService) RevokeTokenByID(ctx context.Context, tokenID, actorUserID string) error {
	// Get token info before revocation
	tok, err := s.store.GetAccessTokenByID(tokenID)
	if err != nil {
		return err
	}

	actorUsername := s.resolveUsername(ctx, actorUserID)

	err = s.store.RevokeToken(tokenID)
	if err != nil {
		// Log revocation failure
		s.auditService.Log(ctx, core.AuditLogEntry{
			EventType:     models.EventTokenRevoked,
			Severity:      models.SeverityError,
			ActorUserID:   actorUserID,
			ActorUsername: actorUsername,
			ResourceType:  models.ResourceToken,
			ResourceID:    tokenID,
			Action:        "Token revocation failed",
			Details:       models.AuditDetails{"token_category": tok.TokenCategory},
			Success:       false,
			ErrorMessage:  err.Error(),
		})
		return err
	}

	s.invalidateTokenCache(ctx, tok.TokenHash)

	// Record revocation
	s.metrics.RecordTokenRevoked(tok.TokenCategory, "user_request")

	// Log token revocation
	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:     models.EventTokenRevoked,
		Severity:      models.SeverityInfo,
		ActorUserID:   actorUserID,
		ActorUsername: actorUsername,
		ResourceType:  models.ResourceToken,
		ResourceID:    tokenID,
		Action:        "Token revoked",
		Details: models.AuditDetails{
			"token_category": tok.TokenCategory,
			"client_id":      tok.ClientID,
			"token_user_id":  tok.UserID,
		},
		Success: true,
	})

	return nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (s *TokenService) RevokeAllUserTokens(userID string) error {
	// Collect hashes before deletion so we can invalidate the cache,
	// but only invalidate if revocation succeeds.
	hashes, err := s.store.GetTokenHashesByUserID(userID)
	if err != nil {
		log.Printf(
			"[TokenCache] failed to collect user token hashes for invalidation user=%s: %v",
			userID, err,
		)
	}

	if err := s.store.RevokeTokensByUserID(userID); err != nil {
		return err
	}

	if len(hashes) > 0 {
		s.invalidateTokenCacheByHashes(context.Background(), hashes)
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

	actorUsername := s.resolveUsername(ctx, actorUserID)

	err = s.store.UpdateTokenStatus(tokenID, newStatus)
	if err != nil {
		// Log failure
		s.auditService.Log(ctx, core.AuditLogEntry{
			EventType:     eventType,
			Severity:      models.SeverityError,
			ActorUserID:   actorUserID,
			ActorUsername: actorUsername,
			ResourceType:  models.ResourceToken,
			ResourceID:    tokenID,
			Action:        actionFailed,
			Details:       models.AuditDetails{"token_category": tok.TokenCategory},
			Success:       false,
			ErrorMessage:  err.Error(),
		})
		return err
	}

	s.invalidateTokenCache(ctx, tok.TokenHash)

	// Log success
	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:     eventType,
		Severity:      models.SeverityInfo,
		ActorUserID:   actorUserID,
		ActorUsername: actorUsername,
		ResourceType:  models.ResourceToken,
		ResourceID:    tokenID,
		Action:        actionSuccess,
		Details: models.AuditDetails{
			"token_category": tok.TokenCategory,
			"client_id":      tok.ClientID,
			"token_user_id":  tok.UserID,
		},
		Success: true,
	})

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
	// Look up token hash for cache invalidation before revoking
	tok, err := s.store.GetAccessTokenByID(tokenID)
	if err != nil {
		return err
	}

	if err := s.store.UpdateTokenStatus(tokenID, models.TokenStatusRevoked); err != nil {
		return err
	}

	s.invalidateTokenCache(context.Background(), tok.TokenHash)

	return nil
}
