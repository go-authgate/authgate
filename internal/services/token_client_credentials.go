package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
)

// IssueClientCredentialsToken issues an access token for the client_credentials grant
// (RFC 6749 §4.4). Only confidential clients with EnableClientCredentialsFlow=true may use
// this flow. No refresh token is issued (per RFC 6749 §4.4.3).
//
// The resulting token carries a synthetic machine identity in UserID: "client:<clientID>".
// This distinguishes M2M tokens from user-delegated tokens in all downstream lookups.
//
// callerExtra (optional) is merged into the issued token; reserved keys must
// already have been rejected by the handler. System claims (project,
// service_account from the OAuth client) override on collision.
func (s *TokenService) IssueClientCredentialsToken(
	ctx context.Context,
	clientID, clientSecret, requestedScopes string,
	callerExtra map[string]any,
) (*models.AccessToken, error) {
	// 1. Look up client (uncached — needs secret for authentication)
	client, err := s.clientService.GetClientWithSecret(ctx, clientID)
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
		// Requested scopes must be a subset of the client's registered scopes
		if !util.IsScopeSubset(client.Scopes, effectiveScopes) {
			return nil, token.ErrInvalidScope
		}
	}

	// 6. Generate access token — synthetic machine identity carries no real user
	start := time.Now()
	machineUserID := "client:" + clientID

	// TokenProfile governs user-delegated access/refresh tokens only.
	// Passing ttl=0 here keeps CLIENT_CREDENTIALS_TOKEN_EXPIRATION as the
	// dedicated authority for M2M token lifetime (independently constrained —
	// typically shorter than user tokens because M2M secrets have a larger
	// blast radius if leaked).
	accessTokenResult, providerErr := s.tokenProvider.GenerateClientCredentialsToken(
		ctx,
		machineUserID,
		clientID,
		effectiveScopes,
		0,
		s.composeIssuanceClaims(client, callerExtra),
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
	s.auditService.Log(ctx, core.AuditLogEntry{
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

	return accessToken, nil
}

// AuthenticateClient verifies client credentials (client_id + client_secret).
// Returns nil on success, or an error if the client is not found, inactive, or the secret is invalid.
func (s *TokenService) AuthenticateClient(
	ctx context.Context,
	clientID, clientSecret string,
) error {
	client, err := s.clientService.GetClientWithSecret(ctx, clientID)
	if err != nil {
		return ErrInvalidClientCredentials
	}
	if !client.IsActive() {
		return ErrInvalidClientCredentials
	}
	if !client.ValidateClientSecret([]byte(clientSecret)) {
		return ErrInvalidClientCredentials
	}
	return nil
}
