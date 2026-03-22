package services

import (
	"context"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"
)

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
