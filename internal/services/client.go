package services

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Client type constants
const (
	ClientTypeConfidential = "confidential"
	ClientTypePublic       = "public"
)

var (
	ErrClientNotFound          = errors.New("client not found")
	ErrInvalidClientData       = errors.New("invalid client data")
	ErrClientNameRequired      = errors.New("client name is required")
	ErrRedirectURIRequired     = errors.New("at least one redirect URI is required when Authorization Code Flow is enabled")
	ErrAtLeastOneGrantRequired = errors.New("at least one grant type must be enabled")
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
	store        *store.Store
	auditService *AuditService
}

func NewClientService(s *store.Store, auditService *AuditService) *ClientService {
	return &ClientService{
		store:        s,
		auditService: auditService,
	}
}

type CreateClientRequest struct {
	ClientName         string
	Description        string
	UserID             string
	Scopes             string
	RedirectURIs       []string
	CreatedBy          string
	ClientType         string // ClientTypeConfidential or ClientTypePublic (default: ClientTypeConfidential)
	EnableDeviceFlow   bool   // Enable Device Authorization Grant (RFC 8628)
	EnableAuthCodeFlow bool   // Enable Authorization Code Flow (RFC 6749)
}

type UpdateClientRequest struct {
	ClientName         string
	Description        string
	Scopes             string
	RedirectURIs       []string
	IsActive           bool
	ClientType         string
	EnableDeviceFlow   bool
	EnableAuthCodeFlow bool
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

	// Generate client ID and secret
	clientID := uuid.New().String()
	clientSecret := uuid.New().String()

	// Hash the secret
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Default scopes
	scopes := strings.TrimSpace(req.Scopes)
	if scopes == "" {
		scopes = "read write"
	}

	// Default client type
	clientType := req.ClientType
	if clientType != ClientTypePublic {
		clientType = ClientTypeConfidential
	}

	// If neither flow is explicitly enabled, default to device flow
	enableDevice := req.EnableDeviceFlow
	enableAuthCode := req.EnableAuthCodeFlow
	if !enableDevice && !enableAuthCode {
		enableDevice = true
	}

	// Derive GrantTypes string from the enabled flows
	var grants []string
	if enableDevice {
		grants = append(grants, "device_code")
	}
	if enableAuthCode {
		grants = append(grants, "authorization_code")
	}
	grantTypes := strings.Join(grants, " ")

	client := &models.OAuthApplication{
		ClientID:           clientID,
		ClientSecret:       string(secretHash),
		ClientName:         strings.TrimSpace(req.ClientName),
		Description:        strings.TrimSpace(req.Description),
		UserID:             req.UserID,
		Scopes:             scopes,
		GrantTypes:         grantTypes,
		RedirectURIs:       models.StringArray(req.RedirectURIs),
		ClientType:         clientType,
		EnableDeviceFlow:   enableDevice,
		EnableAuthCodeFlow: enableAuthCode,
		IsActive:           true,
		CreatedBy:          req.CreatedBy,
	}

	if err := s.store.CreateClient(client); err != nil {
		return nil, err
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

	if !req.EnableDeviceFlow && !req.EnableAuthCodeFlow {
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

	client.ClientName = strings.TrimSpace(req.ClientName)
	client.Description = strings.TrimSpace(req.Description)
	client.Scopes = strings.TrimSpace(req.Scopes)
	client.RedirectURIs = models.StringArray(req.RedirectURIs)
	client.IsActive = req.IsActive

	// Client type defaults to confidential
	if req.ClientType == ClientTypePublic {
		client.ClientType = ClientTypePublic
	} else {
		client.ClientType = ClientTypeConfidential
	}

	// Rebuild GrantTypes from enablement flags
	client.EnableDeviceFlow = req.EnableDeviceFlow
	client.EnableAuthCodeFlow = req.EnableAuthCodeFlow
	var grants []string
	if req.EnableDeviceFlow {
		grants = append(grants, "device_code")
	}
	if req.EnableAuthCodeFlow {
		grants = append(grants, "authorization_code")
	}
	client.GrantTypes = strings.Join(grants, " ")

	err = s.store.UpdateClient(client)
	if err != nil {
		return err
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
				"is_active":   client.IsActive,
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

	err = s.store.DeleteClient(clientID)
	if err != nil {
		return err
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
	newSecret := uuid.New().String()
	secretHash, err := bcrypt.GenerateFromPassword([]byte(newSecret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	client.ClientSecret = string(secretHash)
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

	if err := bcrypt.CompareHashAndPassword(
		[]byte(client.ClientSecret),
		[]byte(clientSecret),
	); err != nil {
		return errors.New("invalid client secret")
	}

	return nil
}

// CountActiveTokens returns the number of active tokens for a given client.
func (s *ClientService) CountActiveTokens(clientID string) (int64, error) {
	return s.store.CountActiveTokensByClientID(clientID)
}
