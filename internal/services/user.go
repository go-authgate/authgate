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
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	storeTypes "github.com/go-authgate/authgate/internal/store/types"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/appleboy/com/random"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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
	ErrOAuthEmailNotVerified     = errors.New(
		"OAuth email not verified and auto-registration is disabled",
	)
	ErrCannotDeleteSelf        = errors.New("cannot delete your own account")
	ErrCannotChangeOwnRole     = errors.New("cannot change your own role")
	ErrCannotRemoveLastAdmin   = errors.New("cannot remove the last admin user")
	ErrPasswordResetNotAllowed = errors.New("password reset only available for local auth users")
	ErrInvalidRole             = errors.New("role must be admin or user")
	ErrEmailRequired           = errors.New("email is required")
	ErrEmailConflict           = errors.New("email already in use by another user")
	ErrAccountDisabled         = errors.New("account is disabled")
	ErrUsernameRequired        = errors.New("username is required")
	ErrCannotDisableSelf       = errors.New("cannot change your own active status")
	ErrUserAlreadyActive       = errors.New("user is already active")
	ErrUserAlreadyDisabled     = errors.New("user is already disabled")
	ErrOAuthConnectionNotFound = errors.New("OAuth connection not found")
)

type UserService struct {
	store             core.Store
	localProvider     core.AuthProvider
	httpAPIProvider   core.AuthProvider
	authMode          string
	oauthAutoRegister bool
	auditService      core.AuditLogger
	userCache         core.Cache[models.User]
	userCacheTTL      time.Duration
}

func NewUserService(
	s core.Store,
	localProvider core.AuthProvider,
	httpAPIProvider core.AuthProvider,
	authMode string,
	oauthAutoRegister bool,
	auditService core.AuditLogger,
	userCache core.Cache[models.User],
	userCacheTTL time.Duration,
) *UserService {
	if auditService == nil {
		auditService = NewNoopAuditService()
	}
	return &UserService{
		store:             s,
		localProvider:     localProvider,
		httpAPIProvider:   httpAPIProvider,
		authMode:          authMode,
		oauthAutoRegister: oauthAutoRegister,
		auditService:      auditService,
		userCache:         userCache,
		userCacheTTL:      userCacheTTL,
	}
}

func (s *UserService) Authenticate(
	ctx context.Context,
	username, password string,
) (*models.User, error) {
	// First, try to find existing user
	existingUser, err := s.store.GetUserByUsername(username)

	// If user exists, check active status then authenticate based on auth_source
	if err == nil {
		if !existingUser.IsActive {
			return nil, ErrAccountDisabled
		}
		return s.authenticateExistingUser(ctx, existingUser, password)
	}

	// User doesn't exist - try to create via external auth if configured
	if s.authMode == AuthModeHTTPAPI {
		return s.authenticateAndCreateExternalUser(ctx, username, password)
	}

	// No existing user and not in external auth mode
	return nil, ErrInvalidCredentials
}

// logAuthFailure logs a failed authentication audit event.
func (s *UserService) logAuthFailure(ctx context.Context, user *models.User, providerName string) {
	s.auditService.Log(ctx, core.AuditLogEntry{
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

// authenticateExistingUser authenticates based on user's auth_source
func (s *UserService) authenticateExistingUser(
	ctx context.Context,
	user *models.User,
	password string,
) (*models.User, error) {
	var authResult *core.AuthResult
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
		if err == nil {
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
		_, err = s.localProvider.Authenticate(ctx, user.Username, password)
	}

	// Handle authentication failure
	if err != nil {
		log.Printf("[Auth] Failed for user=%s provider=%s: %v", user.Username, providerName, err)
		s.logAuthFailure(ctx, user, providerName)
		return nil, ErrInvalidCredentials
	}

	// Log successful authentication
	s.auditService.Log(ctx, core.AuditLogEntry{
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
		s.auditService.Log(ctx, core.AuditLogEntry{
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
		return nil, ErrInvalidCredentials
	}

	// Create new user in local database
	user, err := s.syncExternalUser(authResult, AuthModeHTTPAPI)
	if err != nil {
		log.Printf("[Auth] Failed to create user=%s: %v", username, err)

		// Log user creation failure
		s.auditService.Log(ctx, core.AuditLogEntry{
			EventType:     models.EventAuthenticationFailure,
			Severity:      models.SeverityError,
			ActorUsername: username,
			Action:        "Failed to create external user",
			Details:       models.AuditDetails{"auth_source": AuthModeHTTPAPI},
			Success:       false,
			ErrorMessage:  err.Error(),
		})

		return nil, ErrUserSyncFailed
	}

	log.Printf("[Auth] New external user created: %s", username)

	// Log successful authentication and user creation
	s.auditService.Log(ctx, core.AuditLogEntry{
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

	return user, nil
}

// syncExternalUser creates or updates local user record from external auth result
func (s *UserService) syncExternalUser(
	result *core.AuthResult,
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

	s.InvalidateUserCache(user.ID)
	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	cacheKey := "user:" + id
	fetchFn := func(ctx context.Context, key string) (models.User, error) {
		u, err := s.store.GetUserByID(id)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return models.User{}, ErrUserNotFound
			}
			return models.User{}, err
		}
		// Strip credential material before caching: PasswordHash must never be
		// written to a shared cache backend (Redis) where it could be read if
		// the cache is compromised. GetUserByID callers only need identity/role
		// data, so this field is safe to omit from the cached copy.
		u.PasswordHash = ""
		return *u, nil
	}

	user, err := s.userCache.GetWithFetch(ctx, cacheKey, s.userCacheTTL, fetchFn)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// InvalidateUserCache removes the cached user entry for the given user ID.
// Call this after any mutation to user data to ensure stale data is not served.
func (s *UserService) InvalidateUserCache(id string) {
	if err := s.userCache.Delete(context.Background(), "user:"+id); err != nil {
		log.Printf("[UserCache] Failed to invalidate cache for user=%s: %v", id, err)
	}
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
		if !user.IsActive {
			return nil, ErrAccountDisabled
		}
		// Only auto-link when the provider has verified the email address.
		// Without this check, an attacker who controls an OAuth account with
		// a victim's email could take over the victim's AuthGate account.
		if oauthUserInfo.EmailVerified {
			return s.linkOAuthToExistingUser(ctx, user, provider, oauthUserInfo, token)
		}
		log.Printf(
			"[OAuth] Skipping auto-link for user=%s provider=%s: email not verified by provider",
			user.Username,
			provider,
		)
		// Fall through to auto-register check — treat as new user
		if !s.oauthAutoRegister {
			return nil, ErrOAuthEmailNotVerified
		}
		return s.createUserWithOAuth(ctx, provider, oauthUserInfo, token)
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

	if !user.IsActive {
		return nil, ErrAccountDisabled
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
		s.InvalidateUserCache(user.ID)
	}

	log.Printf("[OAuth] User login: user=%s provider=%s", user.Username, connection.Provider)

	// Log OAuth authentication
	s.auditService.Log(ctx, core.AuditLogEntry{
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
		s.InvalidateUserCache(user.ID)
	}

	log.Printf("[OAuth] Linked existing user: user=%s provider=%s", user.Username, provider)

	// Log OAuth linking
	s.auditService.Log(ctx, core.AuditLogEntry{
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
		Role:         models.UserRoleUser,
		AuthSource:   models.AuthSourceLocal,
		IsActive:     true,
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
	err := s.store.RunInTransaction(func(tx core.Store) error {
		if err := tx.CreateUser(user); err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return fmt.Errorf("email already in use: %s", oauthUserInfo.Email)
			}
			return fmt.Errorf("failed to create user: %w", err)
		}

		if err := tx.CreateOAuthConnection(connection); err != nil {
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
	s.auditService.Log(ctx, core.AuditLogEntry{
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
		candidate := username + "-" + strconv.Itoa(i)
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

// ── Admin User Management ──────────────────────────────────────────────

// UserStats contains aggregate counts for a user's related entities.
type UserStats struct {
	ActiveTokenCount     int64
	OAuthConnectionCount int64
	AuthorizationCount   int64
}

// UpdateUserProfileRequest carries the fields an admin can edit.
type UpdateUserProfileRequest struct {
	FullName string
	Email    string
	Role     string
}

// ListUsersPaginated returns a paginated list of users.
func (s *UserService) ListUsersPaginated(
	params storeTypes.PaginationParams,
) ([]models.User, storeTypes.PaginationResult, error) {
	return s.store.ListUsersPaginated(params)
}

// AdminGetUserByID fetches a user directly from the store (no cache) so that
// auth_source and other mutable fields are always fresh.
func (s *UserService) AdminGetUserByID(userID string) (*models.User, error) {
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

// GetUserStats returns aggregate counts for a user in a single database query.
func (s *UserService) GetUserStats(userID string) (UserStats, error) {
	counts, err := s.store.GetUserStatsByUserID(userID)
	if err != nil {
		return UserStats{}, fmt.Errorf("get user stats: %w", err)
	}
	return UserStats{
		ActiveTokenCount:     counts.ActiveTokenCount,
		OAuthConnectionCount: counts.OAuthConnectionCount,
		AuthorizationCount:   counts.ActiveAuthorizationCount,
	}, nil
}

// UpdateUserProfile updates a user's profile fields. Role changes are blocked
// when actorUserID == userID to prevent admins from demoting themselves.
func (s *UserService) UpdateUserProfile(
	ctx context.Context,
	userID, actorUserID string,
	req UpdateUserProfileRequest,
) error {
	user, err := s.AdminGetUserByID(userID)
	if err != nil {
		return err
	}

	// Validate role
	if req.Role != "" && req.Role != models.UserRoleAdmin && req.Role != models.UserRoleUser {
		return ErrInvalidRole
	}

	// Prevent self role change
	if req.Role != "" && req.Role != user.Role && actorUserID == userID {
		return ErrCannotChangeOwnRole
	}

	// Validate email
	if req.Email == "" {
		return ErrEmailRequired
	}

	// Check email conflict
	if req.Email != user.Email {
		existing, lookupErr := s.store.GetUserByEmail(req.Email)
		if lookupErr != nil {
			if !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
				return fmt.Errorf("failed to check email uniqueness: %w", lookupErr)
			}
		} else if existing.ID != userID {
			return ErrEmailConflict
		}
	}

	// Prevent removing the last admin
	if req.Role != "" && user.Role == models.UserRoleAdmin && req.Role != models.UserRoleAdmin {
		adminCount, err := s.store.CountUsersByRole(models.UserRoleAdmin)
		if err != nil {
			return fmt.Errorf("failed to count admins: %w", err)
		}
		if adminCount <= 1 {
			return ErrCannotRemoveLastAdmin
		}
	}

	oldRole := user.Role
	user.FullName = req.FullName
	user.Email = req.Email
	if req.Role != "" {
		user.Role = req.Role
	}

	if err := s.store.UpdateUser(user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.InvalidateUserCache(userID)

	// Audit logging
	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventUserUpdated,
		Severity:     models.SeverityInfo,
		ActorUserID:  actorUserID,
		ResourceType: models.ResourceUser,
		ResourceID:   userID,
		ResourceName: user.Username,
		Action:       "User profile updated by admin",
		Details: models.AuditDetails{
			"email":     req.Email,
			"full_name": req.FullName,
			"role":      req.Role,
		},
		Success: true,
	})

	if req.Role != "" && oldRole != req.Role {
		s.auditService.Log(ctx, core.AuditLogEntry{
			EventType:    models.EventUserRoleChanged,
			Severity:     models.SeverityWarning,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceUser,
			ResourceID:   userID,
			ResourceName: user.Username,
			Action:       "User role changed by admin",
			Details: models.AuditDetails{
				"old_role": oldRole,
				"new_role": req.Role,
			},
			Success: true,
		})
	}

	return nil
}

// ResetUserPassword generates a new random password for a local-auth user.
// Returns the plaintext password (to be shown once) or an error.
func (s *UserService) ResetUserPassword(
	ctx context.Context,
	userID, actorUserID string,
) (string, error) {
	user, err := s.AdminGetUserByID(userID)
	if err != nil {
		return "", err
	}

	if user.AuthSource != models.AuthSourceLocal {
		return "", ErrPasswordResetNotAllowed
	}

	newPassword, err := util.GenerateRandomPassword(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = string(hash)
	if err := s.store.UpdateUser(user); err != nil {
		return "", fmt.Errorf("failed to update user password: %w", err)
	}

	s.InvalidateUserCache(userID)

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventUserPasswordReset,
		Severity:     models.SeverityWarning,
		ActorUserID:  actorUserID,
		ResourceType: models.ResourceUser,
		ResourceID:   userID,
		ResourceName: user.Username,
		Action:       "User password reset by admin",
		Success:      true,
	})

	return newPassword, nil
}

// ValidateDeleteUser checks whether the user can be deleted without performing
// the deletion. The caller can use this to run pre-deletion side effects (e.g.
// token revocation) before committing the delete.
func (s *UserService) ValidateDeleteUser(userID, actorUserID string) error {
	if actorUserID == userID {
		return ErrCannotDeleteSelf
	}

	user, err := s.AdminGetUserByID(userID)
	if err != nil {
		return err
	}

	if user.Role == models.UserRoleAdmin {
		adminCount, countErr := s.store.CountUsersByRole(models.UserRoleAdmin)
		if countErr != nil {
			return fmt.Errorf("failed to count admins: %w", countErr)
		}
		if adminCount <= 1 {
			return ErrCannotRemoveLastAdmin
		}
	}

	return nil
}

// DeleteUserAdmin deletes a user and cleans up related data. Callers must
// revoke tokens via TokenService before calling this method to ensure token
// cache invalidation. Guards are re-checked for safety.
func (s *UserService) DeleteUserAdmin(
	ctx context.Context,
	userID, actorUserID string,
) error {
	if actorUserID == userID {
		return ErrCannotDeleteSelf
	}

	user, err := s.AdminGetUserByID(userID)
	if err != nil {
		return err
	}

	// Re-check last-admin guard (defense in depth against races).
	if user.Role == models.UserRoleAdmin {
		adminCount, countErr := s.store.CountUsersByRole(models.UserRoleAdmin)
		if countErr != nil {
			return fmt.Errorf("failed to count admins: %w", countErr)
		}
		if adminCount <= 1 {
			return ErrCannotRemoveLastAdmin
		}
	}

	// Clean up user-related data inside a transaction for atomicity.
	if err := s.store.RunInTransaction(func(tx core.Store) error {
		if err := tx.DeleteOAuthConnectionsByUserID(userID); err != nil {
			return fmt.Errorf("delete OAuth connections: %w", err)
		}
		if err := tx.RevokeAllUserAuthorizationsByUserID(userID); err != nil {
			return fmt.Errorf("revoke authorizations: %w", err)
		}
		if err := tx.DeleteUser(userID); err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.InvalidateUserCache(userID)

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventUserDeleted,
		Severity:     models.SeverityWarning,
		ActorUserID:  actorUserID,
		ResourceType: models.ResourceUser,
		ResourceID:   userID,
		ResourceName: user.Username,
		Action:       "User deleted by admin",
		Details: models.AuditDetails{
			"username":    user.Username,
			"email":       user.Email,
			"role":        user.Role,
			"auth_source": user.AuthSource,
		},
		Success: true,
	})

	return nil
}

// CountUsersByRole returns the number of active users with the given role.
// Disabled users are excluded so that last-admin guards work correctly.
func (s *UserService) CountUsersByRole(role string) (int64, error) {
	return s.store.CountUsersByRole(role)
}

// ── Admin Create User ─────────────────────────────────────────────────

// CreateUserRequest carries the fields for admin user creation.
type CreateUserRequest struct {
	Username string
	Email    string
	FullName string
	Role     string
	Password string // optional — if empty, generate random
}

// CreateUserAdmin creates a new local-auth user. Returns the user and
// the plaintext password (to show once).
func (s *UserService) CreateUserAdmin(
	ctx context.Context,
	req CreateUserRequest,
	actorUserID string,
) (*models.User, string, error) {
	// Validate and sanitize required fields
	req.Username = sanitizeUsername(strings.TrimSpace(req.Username))
	req.Email = strings.TrimSpace(req.Email)
	if req.Username == "" {
		return nil, "", ErrUsernameRequired
	}
	if req.Email == "" {
		return nil, "", ErrEmailRequired
	}
	if req.Role == "" {
		req.Role = models.UserRoleUser
	}
	if req.Role != models.UserRoleAdmin && req.Role != models.UserRoleUser {
		return nil, "", ErrInvalidRole
	}

	// Check username uniqueness
	if _, err := s.store.GetUserByUsername(req.Username); err == nil {
		return nil, "", ErrUsernameConflict
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, "", fmt.Errorf("failed to check username uniqueness: %w", err)
	}

	// Check email uniqueness
	if _, err := s.store.GetUserByEmail(req.Email); err == nil {
		return nil, "", ErrEmailConflict
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, "", fmt.Errorf("failed to check email uniqueness: %w", err)
	}

	// Generate password if not provided
	password := req.Password
	if password == "" {
		var err error
		password, err = util.GenerateRandomPassword(16)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate password: %w", err)
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		FullName:     req.FullName,
		Role:         req.Role,
		PasswordHash: string(hash),
		AuthSource:   models.AuthSourceLocal,
		IsActive:     true,
	}

	if err := s.store.CreateUser(user); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// Re-query to determine which unique constraint was violated (race condition).
			if _, emailErr := s.store.GetUserByEmail(req.Email); emailErr == nil {
				return nil, "", ErrEmailConflict
			}
			return nil, "", ErrUsernameConflict
		}
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventUserCreated,
		Severity:     models.SeverityInfo,
		ActorUserID:  actorUserID,
		ResourceType: models.ResourceUser,
		ResourceID:   user.ID,
		ResourceName: user.Username,
		Action:       "User created by admin",
		Details: models.AuditDetails{
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
		Success: true,
	})

	return user, password, nil
}

// ── Admin OAuth Connection Management ─────────────────────────────────

// GetUserOAuthConnections returns all OAuth connections for a user.
func (s *UserService) GetUserOAuthConnections(userID string) ([]models.OAuthConnection, error) {
	return s.store.GetOAuthConnectionsByUserID(userID)
}

// DeleteUserOAuthConnection deletes a specific OAuth connection for a user.
func (s *UserService) DeleteUserOAuthConnection(
	ctx context.Context,
	userID, connectionID, actorUserID string,
) error {
	// Verify the connection belongs to this user with a single indexed query
	target, err := s.store.GetOAuthConnectionByUserAndID(userID, connectionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOAuthConnectionNotFound
		}
		return fmt.Errorf("failed to look up OAuth connection: %w", err)
	}

	if err := s.store.DeleteOAuthConnection(connectionID); err != nil {
		return fmt.Errorf("failed to delete connection: %w", err)
	}

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventOAuthConnectionDeleted,
		Severity:     models.SeverityWarning,
		ActorUserID:  actorUserID,
		ResourceType: models.ResourceUser,
		ResourceID:   userID,
		ResourceName: target.Provider + ":" + target.ProviderUsername,
		Action:       "OAuth connection removed by admin",
		Details: models.AuditDetails{
			"provider":          target.Provider,
			"provider_username": target.ProviderUsername,
			"connection_id":     connectionID,
		},
		Success: true,
	})

	return nil
}

// ── Admin Disable/Enable User ─────────────────────────────────────────

// ValidateSetUserActiveStatus checks whether the active status change is
// allowed without performing it. Callers can use this to run pre-change
// side effects (e.g. token revocation) before committing the update.
func (s *UserService) ValidateSetUserActiveStatus(
	userID, actorUserID string,
	isActive bool,
) error {
	if actorUserID == userID {
		return ErrCannotDisableSelf
	}

	user, err := s.AdminGetUserByID(userID)
	if err != nil {
		return err
	}

	if isActive && user.IsActive {
		return ErrUserAlreadyActive
	}
	if !isActive && !user.IsActive {
		return ErrUserAlreadyDisabled
	}

	if !isActive && user.Role == models.UserRoleAdmin {
		adminCount, countErr := s.store.CountUsersByRole(models.UserRoleAdmin)
		if countErr != nil {
			return fmt.Errorf("failed to count admins: %w", countErr)
		}
		if adminCount <= 1 {
			return ErrCannotRemoveLastAdmin
		}
	}

	return nil
}

// SetUserActiveStatus enables or disables a user account.
func (s *UserService) SetUserActiveStatus(
	ctx context.Context,
	userID, actorUserID string,
	isActive bool,
) error {
	// Re-validate for defense-in-depth (handler calls ValidateSetUserActiveStatus
	// separately so it can skip token revocation on validation failure).
	if err := s.ValidateSetUserActiveStatus(userID, actorUserID, isActive); err != nil {
		return err
	}

	user, err := s.AdminGetUserByID(userID)
	if err != nil {
		return err
	}

	user.IsActive = isActive
	if err := s.store.UpdateUser(user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.InvalidateUserCache(userID)

	eventType := models.EventUserEnabled
	action := "User account enabled by admin"
	severity := models.SeverityInfo
	if !isActive {
		eventType = models.EventUserDisabled
		action = "User account disabled by admin"
		severity = models.SeverityWarning
	}

	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    eventType,
		Severity:     severity,
		ActorUserID:  actorUserID,
		ResourceType: models.ResourceUser,
		ResourceID:   userID,
		ResourceName: user.Username,
		Action:       action,
		Details: models.AuditDetails{
			"username":  user.Username,
			"is_active": isActive,
		},
		Success: true,
	})

	return nil
}
