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

// ExchangeDeviceCode exchanges an authorized device code for access and refresh tokens.
// extraClaims (optional) is merged into both tokens as caller-supplied JWT
// claims; reserved keys must already have been rejected by the handler.
// requestedResource (optional, RFC 8707 §2.2) narrows the access token's
// "aud" — when set, it MUST be a subset of the audience the user authorized
// at /oauth/device/code, otherwise ErrInvalidTarget is returned. When empty,
// the device code's bound resource set is reused unchanged. The refresh
// token always carries the full granted resource set on its DB row so future
// /oauth/token refresh requests can re-narrow against the original grant.
func (s *TokenService) ExchangeDeviceCode(
	ctx context.Context,
	deviceCode, clientID string,
	extraClaims map[string]any,
	requestedResource []string,
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

	// RFC 8707 §2.2: the polling client may narrow the audience but MUST NOT
	// widen it past what the user authorized at /oauth/device/code. An empty
	// authorized set therefore rejects any token-time `resource` (matches the
	// auth-code flow's rule).
	grantedResource := []string(dc.Resource)
	if len(requestedResource) > 0 &&
		!util.IsStringSliceSubset(grantedResource, requestedResource) {
		s.metrics.RecordOAuthDeviceCodeValidation("invalid")
		return nil, nil, ErrInvalidTarget
	}
	accessResource := requestedResource
	if len(accessResource) == 0 {
		accessResource = grantedResource
	}

	// Record successful validation
	s.metrics.RecordOAuthDeviceCodeValidation("success")

	// Resolve the UserAuthorization saved at /device/verify so the issued
	// tokens carry an AuthorizationID FK. This is what makes
	// /account/authorizations cascade-revoke and admin /admin/clients/:id/revoke-all
	// actually invalidate device-code tokens — without it the tokens are
	// orphaned and only expire naturally. A missing UA is non-fatal (we still
	// issue tokens) so older device codes authorized before consent persistence
	// existed continue to work; the only loss is cascade-revoke for that one
	// session.
	var authorizationID *uint
	if ua, err := s.store.GetUserAuthorization(dc.UserID, client.ID); err == nil &&
		ua != nil {
		id := ua.ID
		authorizationID = &id
	}

	// Generate and persist token pair. The refresh token's DB row carries the
	// full granted resource set so future refresh requests can re-narrow
	// against the original /oauth/device/code grant rather than the (possibly
	// narrowed) access-token audience.
	start := time.Now()
	accessToken, refreshToken, err := s.generateAndPersistTokenPair(ctx, tokenPairParams{
		UserID:          dc.UserID,
		ClientID:        dc.ClientID,
		Scopes:          dc.Scopes,
		AuthorizationID: authorizationID,
		Client:          client,
		ExtraClaims:     extraClaims,
		Resource:        accessResource,
		RefreshResource: grantedResource,
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

	// Log token issuance — ActorUsername is auto-resolved by buildAuditLog.
	s.auditService.Log(ctx, core.AuditLogEntry{
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

	s.auditService.Log(ctx, core.AuditLogEntry{
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

	return accessToken, refreshToken, nil
}

// ExchangeAuthorizationCode issues an access token, a refresh token, and (when the openid scope
// was granted) an OIDC ID Token for an already-validated authorization code.
// The AuthorizationCode record must have been validated and marked as used by
// AuthorizationService.ExchangeCode before calling this method.
// extraClaims (optional) is merged into both access and refresh tokens; it
// does NOT affect ID Token claims (those are governed by OIDC scopes).
// resource (optional, RFC 8707) narrows the access token's `aud` claim — it
// MUST be a subset of the authorization code's bound resource set. The
// refresh token's JWT `aud` is unaffected (it is signed with nil audience
// and falls back to the static JWTAudience config); only the refresh-token
// row's persisted Resource column tracks the granted set, for §2.2 subset
// checks on subsequent refresh requests.
// Returns: accessToken, refreshToken, idToken (empty string when openid not requested), error.
func (s *TokenService) ExchangeAuthorizationCode(
	ctx context.Context,
	authCode *models.AuthorizationCode,
	authorizationID *uint,
	extraClaims map[string]any,
	resource []string,
) (*models.AccessToken, *models.AccessToken, string, error) {
	start := time.Now()
	providerName := s.tokenProvider.Name()

	// Load the client once and thread it through token-pair issuance so
	// generateAndPersistTokenPair's TTL resolver doesn't do a second lookup.
	// Failure here is surfaced to the caller — an auth code cannot be
	// exchanged without its client record.
	client, err := s.clientService.GetClient(ctx, authCode.ClientID)
	if err != nil {
		return nil, nil, "", err
	}

	// Defense in depth: re-enforce the RFC 8707 §2.2 subset rule at the
	// service boundary. The handler also validates this via
	// AuthorizationService.ExchangeCode, but ExchangeAuthorizationCode is
	// exported and may be called from other entry points; the audience
	// invariant must hold here too.
	refreshResource := []string(authCode.Resource)
	if !util.IsStringSliceSubset(refreshResource, resource) {
		return nil, nil, "", ErrInvalidTarget
	}

	// The refresh token always carries the full /authorize-time grant so
	// later refreshes can re-narrow against it. The access token gets
	// whatever the /token request narrowed to (or the full grant when /token
	// didn't pass `resource`).
	accessResource := resource
	if len(accessResource) == 0 {
		accessResource = refreshResource
	}

	// Generate and persist token pair (linked to UserAuthorization for cascade-revoke)
	accessToken, refreshToken, err := s.generateAndPersistTokenPair(ctx, tokenPairParams{
		UserID:          authCode.UserID,
		ClientID:        authCode.ClientID,
		Scopes:          authCode.Scopes,
		AuthorizationID: authorizationID,
		Client:          client,
		ExtraClaims:     extraClaims,
		Resource:        accessResource,
		RefreshResource: refreshResource,
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

			// Fetch user profile only when scope-gated claims are needed
			if scopeSet["profile"] || scopeSet["email"] {
				if user, err := s.store.GetUserByID(authCode.UserID); err == nil {
					// Cache the user in context so the audit service's
					// ActorUsername enrichment hits context (no extra DB call).
					ctx = models.SetUserContext(ctx, user)
					if scopeSet["profile"] {
						params.Name = user.FullName
						params.PreferredUsername = user.Username
						params.Picture = user.AvatarURL
						updatedAt := user.UpdatedAt
						params.UpdatedAt = &updatedAt
					}
					if scopeSet["email"] {
						params.Email = user.Email
						params.EmailVerified = user.EmailVerified
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
			} else {
				log.Printf("[Token] ID token generation failed: %v", err)
			}
		}
	}

	// Metrics
	duration := time.Since(start)
	s.metrics.RecordTokenIssued("access", "authorization_code", duration, providerName)
	s.metrics.RecordTokenIssued("refresh", "authorization_code", duration, providerName)

	// Audit — ActorUsername is auto-resolved by buildAuditLog (from the
	// context user cached above when openid+profile/email was requested,
	// or via DB fallback otherwise).
	s.auditService.Log(ctx, core.AuditLogEntry{
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
	s.auditService.Log(ctx, core.AuditLogEntry{
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

	return accessToken, refreshToken, idToken, nil
}
