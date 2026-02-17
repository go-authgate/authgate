package services

import (
	"context"
	"errors"
	"strings"

	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrClientNotFound     = errors.New("client not found")
	ErrInvalidClientData  = errors.New("invalid client data")
	ErrClientNameRequired = errors.New("client name is required")
)

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
	ClientName   string
	Description  string
	UserID       string
	Scopes       string
	GrantTypes   string
	RedirectURIs []string
	CreatedBy    string
}

type UpdateClientRequest struct {
	ClientName   string
	Description  string
	Scopes       string
	GrantTypes   string
	RedirectURIs []string
	IsActive     bool
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

	// Generate client ID and secret
	clientID := uuid.New().String()
	clientSecret := uuid.New().String()

	// Hash the secret
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Set default grant type if not provided
	grantTypes := req.GrantTypes
	if strings.TrimSpace(grantTypes) == "" {
		grantTypes = "device_code"
	}

	// Set default scopes if not provided
	scopes := req.Scopes
	if strings.TrimSpace(scopes) == "" {
		scopes = "read write"
	}

	client := &models.OAuthApplication{
		ClientID:         clientID,
		ClientSecret:     string(secretHash),
		ClientName:       strings.TrimSpace(req.ClientName),
		Description:      strings.TrimSpace(req.Description),
		UserID:           req.UserID,
		Scopes:           strings.TrimSpace(scopes),
		GrantTypes:       strings.TrimSpace(grantTypes),
		RedirectURIs:     models.StringArray(req.RedirectURIs),
		EnableDeviceFlow: true,
		IsActive:         true,
		CreatedBy:        req.CreatedBy,
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

	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	client.ClientName = strings.TrimSpace(req.ClientName)
	client.Description = strings.TrimSpace(req.Description)
	client.Scopes = strings.TrimSpace(req.Scopes)
	client.GrantTypes = strings.TrimSpace(req.GrantTypes)
	client.RedirectURIs = models.StringArray(req.RedirectURIs)
	client.IsActive = req.IsActive

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
