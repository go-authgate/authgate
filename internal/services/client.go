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
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
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
	ErrAtLeastOneGrantRequired              = errors.New("at least one grant type must be enabled")
	ErrClientCredentialsRequireConfidential = errors.New(
		"client credentials flow requires a confidential client",
	)
	ErrClientOwnershipRequired  = errors.New("you do not own this client")
	ErrCannotDeleteActiveClient = errors.New("cannot delete an active client")
	ErrInvalidScopeForUser      = errors.New(
		"scope not allowed for user-created clients",
	)
	ErrInvalidClientStatus = errors.New(
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
	store          core.Store
	auditService   *AuditService
	countCache     core.Cache[int64]
	countCacheTTL  time.Duration
	clientCache    core.Cache[models.OAuthApplication]
	clientCacheTTL time.Duration
}

func NewClientService(
	s core.Store,
	auditService *AuditService,
	countCache core.Cache[int64],
	countCacheTTL time.Duration,
	clientCache core.Cache[models.OAuthApplication],
	clientCacheTTL time.Duration,
) *ClientService {
	if countCache == nil {
		countCache = cache.NewMemoryCache[int64]()
	}
	if countCacheTTL <= 0 {
		countCacheTTL = time.Hour
	}
	if clientCache == nil {
		clientCache = cache.NewMemoryCache[models.OAuthApplication]()
	}
	if clientCacheTTL <= 0 {
		clientCacheTTL = 5 * time.Minute
	}
	return &ClientService{
		store:          s,
		auditService:   auditService,
		countCache:     countCache,
		countCacheTTL:  countCacheTTL,
		clientCache:    clientCache,
		clientCacheTTL: clientCacheTTL,
	}
}

type CreateClientRequest struct {
	ClientName                  string
	Description                 string
	UserID                      string
	Scopes                      string
	RedirectURIs                []string
	CreatedBy                   string
	ClientType                  core.ClientType
	EnableDeviceFlow            bool // Enable Device Authorization Grant (RFC 8628)
	EnableAuthCodeFlow          bool // Enable Authorization Code Flow (RFC 6749)
	EnableClientCredentialsFlow bool // Enable Client Credentials Grant (RFC 6749 §4.4); confidential clients only
	IsAdminCreated              bool // When true: Status=active; when false: Status=pending
}

type UpdateClientRequest struct {
	ClientName                  string
	Description                 string
	Scopes                      string
	RedirectURIs                []string
	Status                      string // "active" or "inactive"
	ClientType                  core.ClientType
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

	clientType := req.ClientType.OrDefault()

	if req.EnableClientCredentialsFlow && clientType != core.ClientTypeConfidential {
		return nil, ErrClientCredentialsRequireConfidential
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

	enableClientCredentials := req.EnableClientCredentialsFlow

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
		ClientType:                  clientType.String(),
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

	s.invalidateClientCache(ctx, clientID)

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
	client.ClientType = clientType.String()

	// Rebuild GrantTypes from enablement flags
	enableClientCredentials := req.EnableClientCredentialsFlow
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

	s.invalidateClientCache(ctx, clientID)

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

	s.invalidateClientCache(ctx, clientID)

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

	// Batch query all users using WHERE IN
	userIDs := util.UniqueKeys(clients, func(c models.OAuthApplication) string { return c.UserID })
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

// GetClient returns a cached OAuth client by client_id.
// The returned copy has ClientSecret cleared for defense-in-depth.
// Use GetClientWithSecret for flows that need secret verification.
// Cache backend failures (e.g. Redis unavailable) are handled transparently:
// the cache layer falls back to the fetch function on any Get error.
func (s *ClientService) GetClient(clientID string) (*models.OAuthApplication, error) {
	client, err := s.clientCache.GetWithFetch(
		context.Background(), clientID, s.clientCacheTTL,
		func(ctx context.Context, _ string) (models.OAuthApplication, error) {
			c, err := s.store.GetClient(clientID)
			if err != nil {
				return models.OAuthApplication{}, err
			}
			// Strip secret material before caching (defense-in-depth)
			cached := *c
			cached.ClientSecret = ""
			return cached, nil
		},
	)
	if err == nil {
		return &client, nil
	}
	return nil, ErrClientNotFound
}

// GetClientWithSecret returns an OAuth client by client_id without caching.
// Use this for flows that need to verify the client secret (e.g., confidential client auth).
func (s *ClientService) GetClientWithSecret(clientID string) (*models.OAuthApplication, error) {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return nil, ErrClientNotFound
	}
	return client, nil
}

// invalidateClientCache removes a client from cache by its client_id.
func (s *ClientService) invalidateClientCache(ctx context.Context, clientID string) {
	if err := s.clientCache.Delete(ctx, clientID); err != nil {
		log.Printf("[ClientCache] Failed to invalidate cache for client=%s: %v", clientID, err)
	}
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

	s.invalidateClientCache(ctx, clientID)

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
	client, err := s.GetClientWithSecret(clientID)
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

	s.invalidateClientCache(ctx, clientID)
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

	s.invalidateClientCache(ctx, clientID)
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
