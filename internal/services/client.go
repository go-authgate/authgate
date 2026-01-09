package services

import (
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
	store *store.Store
}

func NewClientService(s *store.Store) *ClientService {
	return &ClientService{store: s}
}

type CreateClientRequest struct {
	ClientName   string
	Description  string
	Scopes       string
	GrantTypes   string
	RedirectURIs string
	CreatedBy    string
}

type UpdateClientRequest struct {
	ClientName   string
	Description  string
	Scopes       string
	GrantTypes   string
	RedirectURIs string
	IsActive     bool
}

type ClientResponse struct {
	*models.OAuthClient
	ClientSecretPlain string // Only populated on creation
}

func (s *ClientService) CreateClient(req CreateClientRequest) (*ClientResponse, error) {
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

	client := &models.OAuthClient{
		ClientID:     clientID,
		ClientSecret: string(secretHash),
		ClientName:   strings.TrimSpace(req.ClientName),
		Description:  strings.TrimSpace(req.Description),
		Scopes:       strings.TrimSpace(scopes),
		GrantTypes:   strings.TrimSpace(grantTypes),
		RedirectURIs: strings.TrimSpace(req.RedirectURIs),
		IsActive:     true,
		CreatedBy:    req.CreatedBy,
	}

	if err := s.store.CreateClient(client); err != nil {
		return nil, err
	}

	return &ClientResponse{
		OAuthClient:       client,
		ClientSecretPlain: clientSecret,
	}, nil
}

func (s *ClientService) UpdateClient(clientID string, req UpdateClientRequest) error {
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
	client.RedirectURIs = strings.TrimSpace(req.RedirectURIs)
	client.IsActive = req.IsActive

	return s.store.UpdateClient(client)
}

func (s *ClientService) DeleteClient(clientID string) error {
	// Check if client exists
	_, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	return s.store.DeleteClient(clientID)
}

func (s *ClientService) ListClients() ([]models.OAuthClient, error) {
	return s.store.ListClients()
}

func (s *ClientService) GetClient(clientID string) (*models.OAuthClient, error) {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return nil, ErrClientNotFound
	}
	return client, nil
}

func (s *ClientService) RegenerateSecret(clientID string) (string, error) {
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

	return newSecret, nil
}

func (s *ClientService) VerifyClientSecret(clientID, clientSecret string) error {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return ErrClientNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret)); err != nil {
		return errors.New("invalid client secret")
	}

	return nil
}
