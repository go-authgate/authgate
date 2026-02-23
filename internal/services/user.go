package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/appleboy/com/random"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

const (
	AuthModeLocal   = "local"
	AuthModeHTTPAPI = "http_api"
)

var (
	ErrInvalidCredentials        = errors.New("invalid username or password")
	ErrUserNotFound              = errors.New("user not found")
	ErrAuthProviderFailed        = errors.New("authentication provider failed")
	ErrUserSyncFailed            = errors.New("failed to sync user from external provider")
	ErrUsernameConflict          = errors.New("username already exists")
	ErrOAuthAutoRegisterDisabled = errors.New("OAuth auto-registration is disabled")
)

type UserService struct {
	store             *store.Store
	localProvider     *auth.LocalAuthProvider
	httpAPIProvider   *auth.HTTPAPIAuthProvider
	authMode          string
	oauthAutoRegister bool
	auditService      *AuditService
}

func NewUserService(
	s *store.Store,
	localProvider *auth.LocalAuthProvider,
	httpAPIProvider *auth.HTTPAPIAuthProvider,
	authMode string,
	oauthAutoRegister bool,
	auditService *AuditService,
) *UserService {
	return &UserService{
		store:             s,
		localProvider:     localProvider,
		httpAPIProvider:   httpAPIProvider,
		authMode:          authMode,
		oauthAutoRegister: oauthAutoRegister,
		auditService:      auditService,
	}
}

func (s *UserService) Authenticate(
	ctx context.Context,
	username, password string,
) (*models.User, error) {
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
	var authResult *auth.Result
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

		// Log failed authentication
		if s.auditService != nil {
			s.auditService.Log(ctx, AuditLogEntry{
				EventType:     models.EventAuthenticationFailure,
				Severity:      models.SeverityWarning,
				ActorUserID:   user.ID,
				ActorUsername: user.Username,
				ResourceType:  models.ResourceUser,
				ResourceID:    user.ID,
				Action:        "User login attempt failed",
				Details: models.AuditDetails{
					"auth_source": user.AuthSource,
					"provider":    providerName,
				},
				Success:      false,
				ErrorMessage: "Invalid credentials",
			})
		}

		return nil, ErrInvalidCredentials
	}

	if !authResult.Success {
		// Log failed authentication
		if s.auditService != nil {
			s.auditService.Log(ctx, AuditLogEntry{
				EventType:     models.EventAuthenticationFailure,
				Severity:      models.SeverityWarning,
				ActorUserID:   user.ID,
				ActorUsername: user.Username,
				ResourceType:  models.ResourceUser,
				ResourceID:    user.ID,
				Action:        "User login attempt failed",
				Details: models.AuditDetails{
					"auth_source": user.AuthSource,
					"provider":    providerName,
				},
				Success:      false,
				ErrorMessage: "Invalid credentials",
			})
		}

		return nil, ErrInvalidCredentials
	}

	// Log successful authentication
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:     models.EventAuthenticationSuccess,
			Severity:      models.SeverityInfo,
			ActorUserID:   user.ID,
			ActorUsername: user.Username,
			ResourceType:  models.ResourceUser,
			ResourceID:    user.ID,
			Action:        "User login successful",
			Details: models.AuditDetails{
				"auth_source": user.AuthSource,
				"provider":    providerName,
			},
			Success: true,
		})
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
		// Log failed authentication attempt
		if s.auditService != nil {
			s.auditService.Log(ctx, AuditLogEntry{
				EventType:     models.EventAuthenticationFailure,
				Severity:      models.SeverityWarning,
				ActorUsername: username,
				Action:        "External user login attempt failed",
				Details: models.AuditDetails{
					"auth_source": AuthModeHTTPAPI,
					"reason":      "external_auth_error",
				},
				Success:      false,
				ErrorMessage: err.Error(),
			})
		}
		return nil, ErrInvalidCredentials
	}

	if !authResult.Success {
		// Log failed authentication attempt
		if s.auditService != nil {
			s.auditService.Log(ctx, AuditLogEntry{
				EventType:     models.EventAuthenticationFailure,
				Severity:      models.SeverityWarning,
				ActorUsername: username,
				Action:        "External user login attempt failed",
				Details: models.AuditDetails{
					"auth_source": AuthModeHTTPAPI,
					"reason":      "invalid_credentials",
				},
				Success:      false,
				ErrorMessage: "Invalid credentials",
			})
		}
		return nil, ErrInvalidCredentials
	}

	// Create new user in local database
	user, err := s.syncExternalUser(authResult, AuthModeHTTPAPI)
	if err != nil {
		log.Printf("[Auth] Failed to create user=%s: %v", username, err)

		// Log user creation failure
		if s.auditService != nil {
			s.auditService.Log(ctx, AuditLogEntry{
				EventType:     models.EventAuthenticationFailure,
				Severity:      models.SeverityError,
				ActorUsername: username,
				Action:        "Failed to create external user",
				Details:       models.AuditDetails{"auth_source": AuthModeHTTPAPI},
				Success:       false,
				ErrorMessage:  err.Error(),
			})
		}

		return nil, ErrUserSyncFailed
	}

	log.Printf("[Auth] New external user created: %s", username)

	// Log successful authentication and user creation
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:     models.EventAuthenticationSuccess,
			Severity:      models.SeverityInfo,
			ActorUserID:   user.ID,
			ActorUsername: user.Username,
			ResourceType:  models.ResourceUser,
			ResourceID:    user.ID,
			Action:        "New external user created and authenticated",
			Details: models.AuditDetails{
				"auth_source": user.AuthSource,
				"external_id": user.ExternalID,
			},
			Success: true,
		})
	}

	return user, nil
}

// syncExternalUser creates or updates local user record from external auth result
func (s *UserService) syncExternalUser(
	result *auth.Result,
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
		// Check for username conflict
		if errors.Is(err, store.ErrUsernameConflict) {
			return nil, ErrUsernameConflict
		}
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

// AuthenticateWithOAuth authenticates a user via OAuth and creates/updates user account
func (s *UserService) AuthenticateWithOAuth(
	ctx context.Context,
	provider string,
	oauthUserInfo *auth.OAuthUserInfo,
	token *oauth2.Token,
) (*models.User, error) {
	// Validate required fields
	if oauthUserInfo.Email == "" {
		return nil, errors.New("OAuth provider must return email")
	}
	if oauthUserInfo.ProviderUserID == "" {
		return nil, errors.New("OAuth provider must return user ID")
	}

	// 1. Check if OAuth connection exists
	connection, err := s.store.GetOAuthConnection(provider, oauthUserInfo.ProviderUserID)
	if err == nil {
		// Connection exists: update token and return user
		return s.updateOAuthConnectionAndGetUser(ctx, connection, oauthUserInfo, token)
	}

	// 2. Check if user exists with same email
	user, err := s.store.GetUserByEmail(oauthUserInfo.Email)
	if err == nil {
		// User exists: link OAuth to existing user
		return s.linkOAuthToExistingUser(ctx, user, provider, oauthUserInfo, token)
	}

	// 3. Check if auto-registration is enabled
	if !s.oauthAutoRegister {
		return nil, ErrOAuthAutoRegisterDisabled
	}

	// 4. Create new user with OAuth
	return s.createUserWithOAuth(ctx, provider, oauthUserInfo, token)
}

// updateOAuthConnectionAndGetUser updates OAuth connection and returns user
func (s *UserService) updateOAuthConnectionAndGetUser(
	ctx context.Context,
	connection *models.OAuthConnection,
	oauthUserInfo *auth.OAuthUserInfo,
	token *oauth2.Token,
) (*models.User, error) {
	// Update token and metadata
	connection.AccessToken = token.AccessToken
	connection.RefreshToken = token.RefreshToken
	connection.TokenExpiry = token.Expiry
	connection.ProviderUsername = oauthUserInfo.Username
	connection.ProviderEmail = oauthUserInfo.Email
	connection.AvatarURL = oauthUserInfo.AvatarURL
	connection.LastUsedAt = time.Now()

	if err := s.store.UpdateOAuthConnection(connection); err != nil {
		return nil, fmt.Errorf("failed to update OAuth connection: %w", err)
	}

	// Get user
	user, err := s.store.GetUserByID(connection.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found for OAuth connection: %w", err)
	}

	// Sync avatar and name if changed
	updated := false
	if oauthUserInfo.AvatarURL != "" && user.AvatarURL != oauthUserInfo.AvatarURL {
		user.AvatarURL = oauthUserInfo.AvatarURL
		updated = true
	}
	if oauthUserInfo.FullName != "" && user.FullName != oauthUserInfo.FullName {
		user.FullName = oauthUserInfo.FullName
		updated = true
	}
	if updated {
		if err := s.store.UpdateUser(user); err != nil {
			log.Printf("[OAuth] Failed to update user info: %v", err)
			// Continue with login even if update fails
		}
	}

	log.Printf("[OAuth] User login: user=%s provider=%s", user.Username, connection.Provider)

	// Log OAuth authentication
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:     models.EventOAuthAuthentication,
			Severity:      models.SeverityInfo,
			ActorUserID:   user.ID,
			ActorUsername: user.Username,
			ResourceType:  models.ResourceUser,
			ResourceID:    user.ID,
			Action:        "OAuth authentication successful",
			Details: models.AuditDetails{
				"provider":         connection.Provider,
				"provider_user_id": connection.ProviderUserID,
			},
			Success: true,
		})
	}

	return user, nil
}

// linkOAuthToExistingUser links OAuth to an existing user
func (s *UserService) linkOAuthToExistingUser(
	ctx context.Context,
	user *models.User,
	provider string,
	oauthUserInfo *auth.OAuthUserInfo,
	token *oauth2.Token,
) (*models.User, error) {
	// Check if already linked to this provider
	existing, _ := s.store.GetOAuthConnectionByUserAndProvider(user.ID, provider)
	if existing != nil {
		return nil, fmt.Errorf("user already linked to %s account", provider)
	}

	// Create OAuth connection
	connection := &models.OAuthConnection{
		ID:               uuid.New().String(),
		UserID:           user.ID,
		Provider:         provider,
		ProviderUserID:   oauthUserInfo.ProviderUserID,
		ProviderUsername: oauthUserInfo.Username,
		ProviderEmail:    oauthUserInfo.Email,
		AvatarURL:        oauthUserInfo.AvatarURL,
		AccessToken:      token.AccessToken,
		RefreshToken:     token.RefreshToken,
		TokenExpiry:      token.Expiry,
		LastUsedAt:       time.Now(),
	}

	if err := s.store.CreateOAuthConnection(connection); err != nil {
		return nil, fmt.Errorf("failed to link OAuth: %w", err)
	}

	// Update user avatar if empty
	if user.AvatarURL == "" && oauthUserInfo.AvatarURL != "" {
		user.AvatarURL = oauthUserInfo.AvatarURL
		if err := s.store.UpdateUser(user); err != nil {
			log.Printf("[OAuth] Failed to update user avatar: %v", err)
			// Continue with login even if update fails
		}
	}

	log.Printf("[OAuth] Linked existing user: user=%s provider=%s", user.Username, provider)

	// Log OAuth linking
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:     models.EventOAuthAuthentication,
			Severity:      models.SeverityInfo,
			ActorUserID:   user.ID,
			ActorUsername: user.Username,
			ResourceType:  models.ResourceUser,
			ResourceID:    user.ID,
			Action:        "OAuth provider linked to existing user",
			Details: models.AuditDetails{
				"provider":         provider,
				"provider_user_id": oauthUserInfo.ProviderUserID,
			},
			Success: true,
		})
	}

	return user, nil
}

// createUserWithOAuth creates a new user with OAuth
func (s *UserService) createUserWithOAuth(
	ctx context.Context,
	provider string,
	oauthUserInfo *auth.OAuthUserInfo,
	token *oauth2.Token,
) (*models.User, error) {
	// Generate unique username
	username := s.generateUniqueUsername(oauthUserInfo.Username, provider)

	// Create user (no password)
	user := &models.User{
		ID:           uuid.New().String(),
		Username:     username,
		Email:        oauthUserInfo.Email,
		FullName:     oauthUserInfo.FullName,
		AvatarURL:    oauthUserInfo.AvatarURL,
		Role:         "user",
		AuthSource:   "local",
		PasswordHash: "", // OAuth users have no password
	}

	// Create OAuth connection
	connection := &models.OAuthConnection{
		ID:               uuid.New().String(),
		UserID:           user.ID,
		Provider:         provider,
		ProviderUserID:   oauthUserInfo.ProviderUserID,
		ProviderUsername: oauthUserInfo.Username,
		ProviderEmail:    oauthUserInfo.Email,
		AvatarURL:        oauthUserInfo.AvatarURL,
		AccessToken:      token.AccessToken,
		RefreshToken:     token.RefreshToken,
		TokenExpiry:      token.Expiry,
		LastUsedAt:       time.Now(),
	}

	// Use transaction to ensure atomicity
	err := s.store.DB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				return fmt.Errorf("email already in use: %s", oauthUserInfo.Email)
			}
			return fmt.Errorf("failed to create user: %w", err)
		}

		if err := tx.Create(connection).Error; err != nil {
			return fmt.Errorf("failed to create OAuth connection: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Printf("[OAuth] New user created: username=%s email=%s provider=%s",
		user.Username, user.Email, provider)

	// Log new user creation via OAuth
	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:     models.EventOAuthAuthentication,
			Severity:      models.SeverityInfo,
			ActorUserID:   user.ID,
			ActorUsername: user.Username,
			ResourceType:  models.ResourceUser,
			ResourceID:    user.ID,
			Action:        "New user created via OAuth",
			Details: models.AuditDetails{
				"provider":         provider,
				"provider_user_id": oauthUserInfo.ProviderUserID,
				"email":            user.Email,
			},
			Success: true,
		})
	}

	return user, nil
}

// generateUniqueUsername generates a unique username from OAuth username
func (s *UserService) generateUniqueUsername(baseUsername, provider string) string {
	// Sanitize username
	username := sanitizeUsername(baseUsername)

	// Check if available
	if _, err := s.store.GetUserByUsername(username); err != nil {
		return username
	}

	// Try with provider suffix
	username = username + "-" + provider
	if _, err := s.store.GetUserByUsername(username); err != nil {
		return username
	}

	// Try with numbers
	for i := 1; i <= 10; i++ {
		candidate := sanitizeUsername(baseUsername) + "-" + provider + "-" + strconv.Itoa(i)
		if _, err := s.store.GetUserByUsername(candidate); err != nil {
			return candidate
		}
	}

	// Last resort: random suffix
	randomSuffix := random.String(6)
	return username + "-" + randomSuffix
}

// sanitizeUsername removes special characters, keeps only alphanumeric, '_' and '-'.
func sanitizeUsername(username string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' ||
			r == '-' {
			return r
		}
		return -1
	}, username))
}
