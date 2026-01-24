package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
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
}

func NewUserService(
	s *store.Store,
	localProvider *auth.LocalAuthProvider,
	httpAPIProvider *auth.HTTPAPIAuthProvider,
	authMode string,
	oauthAutoRegister bool,
) *UserService {
	return &UserService{
		store:             s,
		localProvider:     localProvider,
		httpAPIProvider:   httpAPIProvider,
		authMode:          authMode,
		oauthAutoRegister: oauthAutoRegister,
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
		return s.updateOAuthConnectionAndGetUser(connection, oauthUserInfo, token)
	}

	// 2. Check if user exists with same email
	user, err := s.store.GetUserByEmail(oauthUserInfo.Email)
	if err == nil {
		// User exists: link OAuth to existing user
		return s.linkOAuthToExistingUser(user, provider, oauthUserInfo, token)
	}

	// 3. Check if auto-registration is enabled
	if !s.oauthAutoRegister {
		return nil, ErrOAuthAutoRegisterDisabled
	}

	// 4. Create new user with OAuth
	return s.createUserWithOAuth(provider, oauthUserInfo, token)
}

// updateOAuthConnectionAndGetUser updates OAuth connection and returns user
func (s *UserService) updateOAuthConnectionAndGetUser(
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
	return user, nil
}

// linkOAuthToExistingUser links OAuth to an existing user
func (s *UserService) linkOAuthToExistingUser(
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
	return user, nil
}

// createUserWithOAuth creates a new user with OAuth
func (s *UserService) createUserWithOAuth(
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

	if err := s.store.CreateUser(user); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return nil, fmt.Errorf("email already in use: %s", oauthUserInfo.Email)
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
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
		// Rollback: delete user
		if deleteErr := s.store.DeleteUser(user.ID); deleteErr != nil {
			log.Printf("[OAuth] Failed to rollback user creation: %v", deleteErr)
		}
		return nil, fmt.Errorf("failed to create OAuth connection: %w", err)
	}

	log.Printf("[OAuth] New user created: username=%s email=%s provider=%s",
		user.Username, user.Email, provider)
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
	username = fmt.Sprintf("%s-%s", username, provider)
	if _, err := s.store.GetUserByUsername(username); err != nil {
		return username
	}

	// Try with numbers
	for i := 1; i <= 10; i++ {
		candidate := fmt.Sprintf("%s-%s-%d", sanitizeUsername(baseUsername), provider, i)
		if _, err := s.store.GetUserByUsername(candidate); err != nil {
			return candidate
		}
	}

	// Last resort: random suffix
	randomSuffix := generateShortRandomString(6)
	return fmt.Sprintf("%s-%s", username, randomSuffix)
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

// generateShortRandomString generates a short random string
func generateShortRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based generation if crypto rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())[:length]
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length]
}
