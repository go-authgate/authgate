package services

import (
	"context"
	"errors"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"
)

// Token status management operations (revoke, disable, enable)

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

// RevokeAllUserTokens revokes all tokens for a user
func (s *TokenService) RevokeAllUserTokens(userID string) error {
	return s.store.RevokeTokensByUserID(userID)
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
