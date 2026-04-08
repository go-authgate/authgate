package services

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"
)

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
	client, err := s.clientService.GetClient(ctx, clientID)
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
	actorUsername := s.resolveUsername(ctx, accessToken.UserID)

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:     models.EventAccessTokenIssued,
		Severity:      models.SeverityInfo,
		ActorUserID:   accessToken.UserID,
		ActorUsername: actorUsername,
		ResourceType:  models.ResourceToken,
		ResourceID:    accessToken.ID,
		Action:        "Access token issued via device code exchange",
		Details: models.AuditDetails{
			"client_id":        accessToken.ClientID,
			"scopes":           accessToken.Scopes,
			"token_provider":   providerName,
			"refresh_token_id": refreshToken.ID,
		},
		Success: true,
	})

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:     models.EventRefreshTokenIssued,
		Severity:      models.SeverityInfo,
		ActorUserID:   refreshToken.UserID,
		ActorUsername: actorUsername,
		ResourceType:  models.ResourceToken,
		ResourceID:    refreshToken.ID,
		Action:        "Refresh token issued via device code exchange",
		Details: models.AuditDetails{
			"client_id":       refreshToken.ClientID,
			"scopes":          refreshToken.Scopes,
			"token_provider":  providerName,
			"access_token_id": accessToken.ID,
		},
		Success: true,
	})

	return accessToken, refreshToken, nil
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

	// Resolve actor username for audit logging. Prefer request context (set by
	// auth middleware); fall back to DB only when context is empty. The user
	// object fetched for ID-token profile claims below is reused so that the
	// sessionless /oauth/token path never issues two GetUserByID calls.
	actorUsername := models.GetUsernameFromContext(ctx)

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

			// Fetch user profile only when scope-gated claims are needed
			if scopeSet["profile"] || scopeSet["email"] {
				if user, err := s.store.GetUserByID(authCode.UserID); err == nil {
					// Reuse the fetched user for actorUsername so we don't
					// need a separate DB call via resolveUsername.
					if actorUsername == "" {
						actorUsername = user.Username
					}
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
				} else {
					log.Printf(
						"[Token] ID token: failed to fetch user profile for user_id=%s, profile/email claims will be omitted: %v",
						authCode.UserID,
						err,
					)
				}
			}

			if generated, err := idp.GenerateIDToken(params); err == nil {
				idToken = generated
				s.auditService.Log(ctx, core.AuditLogEntry{
					EventType:     models.EventIDTokenIssued,
					Severity:      models.SeverityInfo,
					ActorUserID:   authCode.UserID,
					ActorUsername: actorUsername,
					ResourceType:  models.ResourceToken,
					ResourceID:    accessToken.ID,
					Action:        "ID token issued via authorization code exchange",
					Details: models.AuditDetails{
						"client_id":       authCode.ClientID,
						"scopes":          authCode.Scopes,
						"token_provider":  providerName,
						"access_token_id": accessToken.ID,
					},
					Success: true,
				})
			} else {
				log.Printf("[Token] ID token generation failed: %v", err)
			}
		}
	}

	// Fall back to DB lookup only when context had no user and the ID-token
	// profile/email path above did not already populate actorUsername.
	if actorUsername == "" {
		actorUsername = s.resolveUsername(ctx, authCode.UserID)
	}

	// Metrics
	duration := time.Since(start)
	s.metrics.RecordTokenIssued("access", "authorization_code", duration, providerName)
	s.metrics.RecordTokenIssued("refresh", "authorization_code", duration, providerName)

	// Audit
	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:     models.EventAccessTokenIssued,
		Severity:      models.SeverityInfo,
		ActorUserID:   accessToken.UserID,
		ActorUsername: actorUsername,
		ResourceType:  models.ResourceToken,
		ResourceID:    accessToken.ID,
		Action:        "Access token issued via authorization code exchange",
		Details: models.AuditDetails{
			"client_id":        accessToken.ClientID,
			"scopes":           accessToken.Scopes,
			"token_provider":   providerName,
			"refresh_token_id": refreshToken.ID,
		},
		Success: true,
	})
	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:     models.EventRefreshTokenIssued,
		Severity:      models.SeverityInfo,
		ActorUserID:   refreshToken.UserID,
		ActorUsername: actorUsername,
		ResourceType:  models.ResourceToken,
		ResourceID:    refreshToken.ID,
		Action:        "Refresh token issued via authorization code exchange",
		Details: models.AuditDetails{
			"client_id":       refreshToken.ClientID,
			"scopes":          refreshToken.Scopes,
			"token_provider":  providerName,
			"access_token_id": accessToken.ID,
		},
		Success: true,
	})

	return accessToken, refreshToken, idToken, nil
}
