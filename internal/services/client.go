package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/google/uuid"
)

// Client type constants
const (
	ClientTypeConfidential = "confidential"
	ClientTypePublic       = "public"
)

const pendingClientsCountCacheKey = "clients:pending_count"

// buildGrantTypes derives the GrantTypes string from per-flow enable flags.
func buildGrantTypes(enableDevice, enableAuthCode, enableClientCredentials bool) string {
	var grants []string
	if enableDevice {
		grants = append(grants, "device_code")
	}
	if enableAuthCode {
		grants = append(grants, "authorization_code")
	}
	if enableClientCredentials {
		grants = append(grants, "client_credentials")
	}
	return strings.Join(grants, " ")
}

// allowedUserScopes are the scopes that non-admin users may request.
var allowedUserScopes = map[string]bool{
	"email":          true,
	"profile":        true,
	"openid":         true,
	"offline_access": true,
}

var (
	ErrClientNotFound      = errors.New("client not found")
	ErrInvalidClientData   = errors.New("invalid client data")
	ErrClientNameRequired  = errors.New("client name is required")
	ErrRedirectURIRequired = errors.New(
		"at least one redirect URI is required when Authorization Code Flow is enabled",
	)
	ErrAtLeastOneGrantRequired  = errors.New("at least one grant type must be enabled")
	ErrClientOwnershipRequired  = errors.New("you do not own this client")
	ErrCannotDeleteActiveClient = errors.New("cannot delete an active client")
	ErrInvalidScopeForUser      = errors.New("scope not allowed for user-created clients")
	ErrInvalidClientStatus      = errors.New(
		"status must be \"active\", \"inactive\", or \"pending\"",
	)
)

// validateRedirectURIs checks that every URI in the slice is an absolute http/https
// URI without a fragment, as required by RFC 6749.
func validateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("%w: URI must not be empty", ErrInvalidRedirectURI)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("%w: %q is not a valid URI", ErrInvalidRedirectURI, raw)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%w: %q must use http or https scheme", ErrInvalidRedirectURI, raw)
		}
		if u.Host == "" {
			return fmt.Errorf("%w: %q must have a host", ErrInvalidRedirectURI, raw)
		}
		if u.Fragment != "" {
			return fmt.Errorf("%w: %q must not contain a fragment", ErrInvalidRedirectURI, raw)
		}
	}
	return nil
}

type ClientService struct {
	store         *store.Store
	auditService  *AuditService
	countCache    core.Cache[int64]
	countCacheTTL time.Duration
}

func NewClientService(
	s *store.Store,
	auditService *AuditService,
	countCache core.Cache[int64],
	countCacheTTL time.Duration,
) *ClientService {
	if countCache == nil {
		countCache = cache.NewMemoryCache[int64]()
	}
	if countCacheTTL <= 0 {
		countCacheTTL = time.Hour
	}
	return &ClientService{
		store:         s,
		auditService:  auditService,
		countCache:    countCache,
		countCacheTTL: countCacheTTL,
	}
}

type CreateClientRequest struct {
	ClientName                  string
	Description                 string
	UserID                      string
	Scopes                      string
	RedirectURIs                []string
	CreatedBy                   string
	ClientType                  string // ClientTypeConfidential or ClientTypePublic (default: ClientTypeConfidential)
	EnableDeviceFlow            bool   // Enable Device Authorization Grant (RFC 8628)
	EnableAuthCodeFlow          bool   // Enable Authorization Code Flow (RFC 6749)
	EnableClientCredentialsFlow bool   // Enable Client Credentials Grant (RFC 6749 §4.4); confidential clients only
	IsAdminCreated              bool   // When true: Status=active; when false: Status=pending
}

// UserUpdateClientRequest contains the restricted set of fields a non-admin user may update on their own client.
type UserUpdateClientRequest struct {
	ClientName         string
	Description        string
	Scopes             string // validated against allowedUserScopes
	RedirectURIs       []string
	ClientType         string
	EnableDeviceFlow   bool
	EnableAuthCodeFlow bool
}

type UpdateClientRequest struct {
	ClientName                  string
	Description                 string
	Scopes                      string
	RedirectURIs                []string
	Status                      string // "active" or "inactive"
	ClientType                  string
	EnableDeviceFlow            bool
	EnableAuthCodeFlow          bool
	EnableClientCredentialsFlow bool // Enable Client Credentials Grant (RFC 6749 §4.4); confidential clients only
}

type ClientResponse struct {
	*models.OAuthApplication
	ClientSecretPlain string // Only populated on creation
}

// ClientWithCreator combines OAuth client and creator user information for display
type ClientWithCreator struct {
	models.OAuthApplication
	CreatorUsername string // Empty string if user not found or deleted
}

func (s *ClientService) CreateClient(
	ctx context.Context,
	req CreateClientRequest,
) (*ClientResponse, error) {
	if strings.TrimSpace(req.ClientName) == "" {
		return nil, ErrClientNameRequired
	}

	if req.EnableAuthCodeFlow && len(req.RedirectURIs) == 0 {
		return nil, ErrRedirectURIRequired
	}

	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		return nil, err
	}

	// Generate client ID
	clientID := uuid.New().String()

	// Default scopes
	scopes := strings.TrimSpace(req.Scopes)
	if scopes == "" {
		scopes = "email profile"
	}

	// Default client type
	clientType := req.ClientType
	if clientType != ClientTypePublic {
		clientType = ClientTypeConfidential
	}

	// Client credentials flow is only available for confidential clients
	enableClientCredentials := req.EnableClientCredentialsFlow &&
		clientType == ClientTypeConfidential

	// If neither flow is explicitly enabled, default to device flow
	enableDevice := req.EnableDeviceFlow
	enableAuthCode := req.EnableAuthCodeFlow
	if !enableDevice && !enableAuthCode && !enableClientCredentials {
		enableDevice = true
	}

	// Derive GrantTypes string from the enabled flows
	grantTypes := buildGrantTypes(enableDevice, enableAuthCode, enableClientCredentials)

	// Determine approval status based on creator role.
	// Admin-created clients are immediately active; user-created clients require approval.
	clientStatus := models.ClientStatusPending
	if req.IsAdminCreated {
		clientStatus = models.ClientStatusActive
	}

	client := &models.OAuthApplication{
		ClientID:                    clientID,
		ClientName:                  strings.TrimSpace(req.ClientName),
		Description:                 strings.TrimSpace(req.Description),
		UserID:                      req.UserID,
		Scopes:                      scopes,
		GrantTypes:                  grantTypes,
		RedirectURIs:                models.StringArray(req.RedirectURIs),
		ClientType:                  clientType,
		EnableDeviceFlow:            enableDevice,
		EnableAuthCodeFlow:          enableAuthCode,
		EnableClientCredentialsFlow: enableClientCredentials,
		Status:                      clientStatus,
		CreatedBy:                   req.CreatedBy,
	}

	// Generate client secret
	clientSecret, err := client.GenerateClientSecret(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.store.CreateClient(client); err != nil {
		return nil, err
	}

	// A new pending client changes the count; invalidate the cache.
	if clientStatus == models.ClientStatusPending {
		s.invalidatePendingCount(ctx)
	}

	// Log client creation
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientCreated,
			Severity:     models.SeverityInfo,
			ActorUserID:  req.CreatedBy,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client created",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
				"grant_types": client.GrantTypes,
				"scopes":      client.Scopes,
			},
			Success: true,
		})
	}

	return &ClientResponse{
		OAuthApplication:  client,
		ClientSecretPlain: clientSecret,
	}, nil
}

func (s *ClientService) UpdateClient(
	ctx context.Context,
	clientID, actorUserID string,
	req UpdateClientRequest,
) error {
	if strings.TrimSpace(req.ClientName) == "" {
		return ErrClientNameRequired
	}

	if !req.EnableDeviceFlow && !req.EnableAuthCodeFlow && !req.EnableClientCredentialsFlow {
		return ErrAtLeastOneGrantRequired
	}

	if req.EnableAuthCodeFlow && len(req.RedirectURIs) == 0 {
		return ErrRedirectURIRequired
	}

	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		return err
	}

	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	switch req.Status {
	case models.ClientStatusActive, models.ClientStatusInactive, models.ClientStatusPending:
		// valid
	default:
		return ErrInvalidClientStatus
	}

	// Record whether the pending count could change before mutating.
	pendingCountAffected := client.Status == models.ClientStatusPending ||
		req.Status == models.ClientStatusPending

	client.ClientName = strings.TrimSpace(req.ClientName)
	client.Description = strings.TrimSpace(req.Description)
	client.Scopes = strings.TrimSpace(req.Scopes)
	client.RedirectURIs = models.StringArray(req.RedirectURIs)
	client.Status = req.Status

	// Client type defaults to confidential
	if req.ClientType == ClientTypePublic {
		client.ClientType = ClientTypePublic
	} else {
		client.ClientType = ClientTypeConfidential
	}

	// Rebuild GrantTypes from enablement flags
	// Client credentials flow is restricted to confidential clients
	enableClientCredentials := req.EnableClientCredentialsFlow &&
		client.ClientType == ClientTypeConfidential
	client.EnableDeviceFlow = req.EnableDeviceFlow
	client.EnableAuthCodeFlow = req.EnableAuthCodeFlow
	client.EnableClientCredentialsFlow = enableClientCredentials
	client.GrantTypes = buildGrantTypes(
		req.EnableDeviceFlow,
		req.EnableAuthCodeFlow,
		enableClientCredentials,
	)

	err = s.store.UpdateClient(client)
	if err != nil {
		return err
	}

	if pendingCountAffected {
		s.invalidatePendingCount(ctx)
	}

	// Log client update
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientUpdated,
			Severity:     models.SeverityInfo,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client updated",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
				"status":      client.Status,
				"grant_types": client.GrantTypes,
				"scopes":      client.Scopes,
			},
			Success: true,
		})
	}

	return nil
}

func (s *ClientService) DeleteClient(ctx context.Context, clientID, actorUserID string) error {
	// Check if client exists
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	wasPending := client.Status == models.ClientStatusPending

	err = s.store.DeleteClient(clientID)
	if err != nil {
		return err
	}

	if wasPending {
		s.invalidatePendingCount(ctx)
	}

	// Log client deletion
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientDeleted,
			Severity:     models.SeverityWarning,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client deleted",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
			},
			Success: true,
		})
	}

	return nil
}

func (s *ClientService) ListClients() ([]models.OAuthApplication, error) {
	return s.store.ListClients()
}

// ListClientsPaginated returns paginated OAuth clients with search support
func (s *ClientService) ListClientsPaginated(
	params store.PaginationParams,
) ([]models.OAuthApplication, store.PaginationResult, error) {
	return s.store.ListClientsPaginated(params)
}

// ListClientsPaginatedWithCreator returns paginated OAuth clients with creator information
// This method prevents N+1 queries by batch loading users via GetUsersByIDs
func (s *ClientService) ListClientsPaginatedWithCreator(
	params store.PaginationParams,
) ([]ClientWithCreator, store.PaginationResult, error) {
	// Step 1: Get paginated clients
	clients, pagination, err := s.store.ListClientsPaginated(params)
	if err != nil {
		return nil, store.PaginationResult{}, err
	}

	if len(clients) == 0 {
		return []ClientWithCreator{}, pagination, nil
	}

	// Step 2: Collect unique user IDs
	userIDSet := make(map[string]bool)
	for _, client := range clients {
		if client.UserID != "" {
			userIDSet[client.UserID] = true
		}
	}

	// Step 3: Convert set to slice
	userIDs := make([]string, 0, len(userIDSet))
	for userID := range userIDSet {
		userIDs = append(userIDs, userID)
	}

	// Step 4: Batch query all users using WHERE IN
	userMap, err := s.store.GetUsersByIDs(userIDs)
	if err != nil {
		return nil, store.PaginationResult{}, err
	}

	// Step 5: Combine clients with user information
	result := make([]ClientWithCreator, 0, len(clients))
	for _, client := range clients {
		username := "" // Default to empty if user not found
		if client.UserID != "" {
			if user, ok := userMap[client.UserID]; ok && user != nil {
				username = user.Username
			}
		}

		result = append(result, ClientWithCreator{
			OAuthApplication: client,
			CreatorUsername:  username,
		})
	}

	return result, pagination, nil
}

func (s *ClientService) GetClient(clientID string) (*models.OAuthApplication, error) {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return nil, ErrClientNotFound
	}
	return client, nil
}

func (s *ClientService) RegenerateSecret(
	ctx context.Context,
	clientID, actorUserID string,
) (string, error) {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return "", ErrClientNotFound
	}

	// Generate new secret
	newSecret, err := client.GenerateClientSecret(ctx)
	if err != nil {
		return "", err
	}

	if err := s.store.UpdateClient(client); err != nil {
		return "", err
	}

	// Log secret regeneration
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientSecretRegenerated,
			Severity:     models.SeverityWarning,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client secret regenerated",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
			},
			Success: true,
		})
	}

	return newSecret, nil
}

func (s *ClientService) VerifyClientSecret(clientID, clientSecret string) error {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	if !client.ValidateClientSecret([]byte(clientSecret)) {
		return errors.New("invalid client secret")
	}

	return nil
}

// CountActiveTokens returns the number of active tokens for a given client.
func (s *ClientService) CountActiveTokens(clientID string) (int64, error) {
	return s.store.CountActiveTokensByClientID(clientID)
}

// CountPendingClients returns the number of clients awaiting admin approval.
// Results are cached for countCacheTTL and invalidated on approve/reject/create/delete.
func (s *ClientService) CountPendingClients(ctx context.Context) (int64, error) {
	return s.countCache.GetWithFetch(ctx, pendingClientsCountCacheKey, s.countCacheTTL,
		func(ctx context.Context, _ string) (int64, error) {
			return s.store.CountClientsByStatus(models.ClientStatusPending)
		})
}

// ListClientsByUser returns paginated OAuth clients owned by the given user.
func (s *ClientService) ListClientsByUser(
	userID string,
	params store.PaginationParams,
) ([]models.OAuthApplication, store.PaginationResult, error) {
	return s.store.ListClientsByUserID(userID, params)
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

	if !req.EnableDeviceFlow && !req.EnableAuthCodeFlow {
		return ErrAtLeastOneGrantRequired
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

	if req.ClientType == ClientTypePublic {
		client.ClientType = ClientTypePublic
	} else {
		client.ClientType = ClientTypeConfidential
	}

	client.EnableDeviceFlow = req.EnableDeviceFlow
	client.EnableAuthCodeFlow = req.EnableAuthCodeFlow
	// User-created clients cannot enable client credentials flow.
	client.EnableClientCredentialsFlow = false
	client.GrantTypes = buildGrantTypes(req.EnableDeviceFlow, req.EnableAuthCodeFlow, false)

	if err := s.store.UpdateClient(client); err != nil {
		return err
	}

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

// ApproveClient sets a client's status to active and enables it for OAuth flows.
func (s *ClientService) ApproveClient(
	ctx context.Context,
	clientID, adminUserID string,
) error {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	client.Status = models.ClientStatusActive

	if err := s.store.UpdateClient(client); err != nil {
		return err
	}

	s.invalidatePendingCount(ctx)

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientApproved,
			Severity:     models.SeverityInfo,
			ActorUserID:  adminUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client approved",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
			},
			Success: true,
		})
	}

	return nil
}

// invalidatePendingCount removes the cached pending-client count so the next
// call to CountPendingClients fetches a fresh value from the database.
func (s *ClientService) invalidatePendingCount(ctx context.Context) {
	if err := s.countCache.Delete(ctx, pendingClientsCountCacheKey); err != nil {
		log.Printf("[ClientCache] Failed to invalidate pending count cache: %v", err)
	}
}

// RejectClient sets a client's status to inactive and disables it for OAuth flows.
func (s *ClientService) RejectClient(
	ctx context.Context,
	clientID, adminUserID string,
) error {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	client.Status = models.ClientStatusInactive

	if err := s.store.UpdateClient(client); err != nil {
		return err
	}

	s.invalidatePendingCount(ctx)

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventClientRejected,
			Severity:     models.SeverityInfo,
			ActorUserID:  adminUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			ResourceName: client.ClientName,
			Action:       "OAuth client rejected",
			Details: models.AuditDetails{
				"client_name": client.ClientName,
			},
			Success: true,
		})
	}

	return nil
}
