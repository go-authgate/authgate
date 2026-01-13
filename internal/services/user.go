package services

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"
)

const (
	AuthModeLocal   = "local"
	AuthModeHTTPAPI = "http_api"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrAuthProviderFailed = errors.New("authentication provider failed")
	ErrUserSyncFailed     = errors.New("failed to sync user from external provider")
)

type UserService struct {
	store           *store.Store
	localProvider   *auth.LocalAuthProvider
	httpAPIProvider *auth.HTTPAPIAuthProvider
	authMode        string
}

func NewUserService(
	s *store.Store,
	localProvider *auth.LocalAuthProvider,
	httpAPIProvider *auth.HTTPAPIAuthProvider,
	authMode string,
) *UserService {
	return &UserService{
		store:           s,
		localProvider:   localProvider,
		httpAPIProvider: httpAPIProvider,
		authMode:        authMode,
	}
}

func (s *UserService) Authenticate(ctx context.Context, username, password string) (*models.User, error) {
	// First, try to find existing user
	existingUser, err := s.store.GetUserByUsername(username)

	// If user exists, authenticate based on their auth_source
	if err == nil {
		return s.authenticateExistingUser(ctx, existingUser, password)
	}

	// User doesn't exist - try to create via external auth if configured
	if s.authMode == AuthModeHTTPAPI {
		return s.authenticateAndCreateExternalUser(ctx, username, password)
	}

	// No existing user and not in external auth mode
	return nil, ErrInvalidCredentials
}

// authenticateExistingUser authenticates based on user's auth_source
func (s *UserService) authenticateExistingUser(
	ctx context.Context,
	user *models.User,
	password string,
) (*models.User, error) {
	var authResult *auth.AuthResult
	var err error
	var providerName string

	// Route based on user's auth_source field
	switch user.AuthSource {
	case AuthModeHTTPAPI:
		if s.httpAPIProvider == nil {
			return nil, fmt.Errorf("%w: HTTP API provider not configured", ErrAuthProviderFailed)
		}
		providerName = "HTTP API"
		authResult, err = s.httpAPIProvider.Authenticate(ctx, user.Username, password)

		// Sync user data on successful external auth
		if err == nil && authResult.Success {
			updatedUser, syncErr := s.syncExternalUser(authResult, AuthModeHTTPAPI)
			if syncErr != nil {
				log.Printf("[Auth] Sync failed for user=%s: %v", user.Username, syncErr)
			} else {
				user = updatedUser
			}
		}

	case AuthModeLocal:
		fallthrough
	default:
		if s.localProvider == nil {
			return nil, fmt.Errorf("%w: local provider not configured", ErrAuthProviderFailed)
		}
		providerName = AuthModeLocal
		authResult, err = s.localProvider.Authenticate(ctx, user.Username, password)
	}

	// Handle authentication failure
	if err != nil {
		log.Printf("[Auth] Failed for user=%s provider=%s: %v", user.Username, providerName, err)
		return nil, ErrInvalidCredentials
	}

	if !authResult.Success {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// authenticateAndCreateExternalUser tries external auth and creates new user
func (s *UserService) authenticateAndCreateExternalUser(
	ctx context.Context,
	username, password string,
) (*models.User, error) {
	if s.httpAPIProvider == nil {
		return nil, fmt.Errorf("%w: HTTP API provider not configured", ErrAuthProviderFailed)
	}

	// Try external authentication
	authResult, err := s.httpAPIProvider.Authenticate(ctx, username, password)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !authResult.Success {
		return nil, ErrInvalidCredentials
	}

	// Create new user in local database
	user, err := s.syncExternalUser(authResult, AuthModeHTTPAPI)
	if err != nil {
		log.Printf("[Auth] Failed to create user=%s: %v", username, err)
		return nil, ErrUserSyncFailed
	}

	log.Printf("[Auth] New external user created: %s", username)
	return user, nil
}

// syncExternalUser creates or updates local user record from external auth result
func (s *UserService) syncExternalUser(
	result *auth.AuthResult,
	authSource string,
) (*models.User, error) {
	user, err := s.store.UpsertExternalUser(
		result.Username,
		result.ExternalID,
		authSource,
		result.Email,
		result.FullName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert external user: %w", err)
	}

	return user, nil
}

func (s *UserService) GetUserByID(id string) (*models.User, error) {
	user, err := s.store.GetUserByID(id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}
