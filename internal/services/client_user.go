package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
)

// User self-service client management (implements restricted operations for non-admin users)

// UserUpdateClientRequest contains the restricted set of fields a non-admin user may update on their own client.
type UserUpdateClientRequest struct {
	ClientName                  string
	Description                 string
	Scopes                      string // validated against allowedUserScopes
	RedirectURIs                []string
	ClientType                  core.ClientType
	EnableDeviceFlow            bool
	EnableAuthCodeFlow          bool
	EnableClientCredentialsFlow bool // Enable Client Credentials Grant (RFC 6749 §4.4); confidential clients only
}

// validateUserScopes checks that all requested scopes are in the allowed set for user-created clients.
func validateUserScopes(scopes string) error {
	for scope := range strings.FieldsSeq(scopes) {
		if !allowedUserScopes[scope] {
			return fmt.Errorf("%w: %q", ErrInvalidScopeForUser, scope)
		}
	}
	return nil
}

// ListClientsByUser returns paginated OAuth clients owned by the given user.
func (s *ClientService) ListClientsByUser(
	userID string,
	params store.PaginationParams,
) ([]models.OAuthApplication, store.PaginationResult, error) {
	return s.store.ListClientsByUserID(userID, params)
}

// UserUpdateClient updates a client owned by actorUserID with the restricted field set.
// Ownership is enforced; the approval Status is never changed by this method.
func (s *ClientService) UserUpdateClient(
	ctx context.Context,
	clientID, actorUserID string,
	req UserUpdateClientRequest,
) error {
	if strings.TrimSpace(req.ClientName) == "" {
		return ErrClientNameRequired
	}

	clientType := req.ClientType.OrDefault()

	if !req.EnableDeviceFlow && !req.EnableAuthCodeFlow && !req.EnableClientCredentialsFlow {
		return ErrAtLeastOneGrantRequired
	}

	if req.EnableClientCredentialsFlow && clientType != core.ClientTypeConfidential {
		return ErrClientCredentialsRequireConfidential
	}

	if req.EnableAuthCodeFlow && len(req.RedirectURIs) == 0 {
		return ErrRedirectURIRequired
	}

	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		return err
	}

	if err := validateUserScopes(req.Scopes); err != nil {
		return err
	}

	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	if client.UserID != actorUserID {
		return ErrClientOwnershipRequired
	}

	client.ClientName = strings.TrimSpace(req.ClientName)
	client.Description = strings.TrimSpace(req.Description)
	client.Scopes = strings.TrimSpace(req.Scopes)
	client.RedirectURIs = models.StringArray(req.RedirectURIs)
	client.ClientType = clientType.String()

	client.EnableDeviceFlow = req.EnableDeviceFlow
	client.EnableAuthCodeFlow = req.EnableAuthCodeFlow
	enableClientCredentials := req.EnableClientCredentialsFlow
	client.EnableClientCredentialsFlow = enableClientCredentials
	client.GrantTypes = buildGrantTypes(
		req.EnableDeviceFlow,
		req.EnableAuthCodeFlow,
		enableClientCredentials,
	)

	if err := s.store.UpdateClient(client); err != nil {
		return err
	}

	s.invalidateClientCache(ctx, clientID)

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientUpdated,
			Severity:     models.SeverityInfo,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client updated by owner",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
				"grant_types": client.GrantTypes,
				"scopes":      client.Scopes,
			},
			Success: true,
		})
	}

	return nil
}

// UserDeleteClient deletes a client owned by actorUserID.
// Deletion is blocked for clients with Status=active (must be rejected first).
func (s *ClientService) UserDeleteClient(
	ctx context.Context,
	clientID, actorUserID string,
) error {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	if client.UserID != actorUserID {
		return ErrClientOwnershipRequired
	}

	if client.Status == models.ClientStatusActive {
		return ErrCannotDeleteActiveClient
	}

	wasPending := client.Status == models.ClientStatusPending

	if err := s.store.DeleteClient(clientID); err != nil {
		return err
	}

	s.invalidateClientCache(ctx, clientID)

	if wasPending {
		s.invalidatePendingCount(ctx)
	}

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientDeleted,
			Severity:     models.SeverityWarning,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client deleted by owner",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
			},
			Success: true,
		})
	}

	return nil
}
