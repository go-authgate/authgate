package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/util"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Authorization Code Flow errors
var (
	ErrInvalidAuthCodeRequest  = errors.New("invalid_request")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrAccessDeniedConsent     = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidAuthCodeScope    = errors.New("invalid_scope")
	ErrInvalidRedirectURI      = errors.New("invalid redirect_uri")
	ErrAuthCodeNotFound        = errors.New("authorization code not found")
	ErrAuthCodeExpired         = errors.New("authorization code expired")
	ErrAuthCodeAlreadyUsed     = errors.New("authorization code already used")
	ErrInvalidCodeVerifier     = errors.New("invalid code_verifier")
	ErrPKCERequired            = errors.New("pkce required for public clients")
	ErrAuthorizationNotFound   = errors.New("authorization not found")
)

// AuthorizationRequest holds validated parameters for an authorization request
type AuthorizationRequest struct {
	Client              *models.OAuthApplication
	RedirectURI         string
	Scopes              string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizationService manages the OAuth 2.0 Authorization Code Flow (RFC 6749)
type AuthorizationService struct {
	store        *store.Store
	config       *config.Config
	auditService *AuditService
}

func NewAuthorizationService(
	s *store.Store,
	cfg *config.Config,
	auditService *AuditService,
) *AuthorizationService {
	return &AuthorizationService{
		store:        s,
		config:       cfg,
		auditService: auditService,
	}
}

// ValidateAuthorizationRequest validates all parameters of an incoming authorization request.
// Returns the parsed AuthorizationRequest on success.
func (s *AuthorizationService) ValidateAuthorizationRequest(
	clientID, redirectURI, responseType, scope, codeChallengeMethod string,
) (*AuthorizationRequest, error) {
	// 1. response_type must be "code"
	if responseType != "code" {
		return nil, ErrUnsupportedResponseType
	}

	// 2. Client must exist and be active
	client, err := s.store.GetClient(clientID)
	if err != nil || !client.IsActive {
		return nil, ErrUnauthorizedClient
	}

	// 3. Auth Code Flow must be enabled for this client
	if !client.EnableAuthCodeFlow {
		return nil, ErrUnauthorizedClient
	}

	// 4. redirect_uri must exactly match one of the registered URIs
	if !s.isValidRedirectURI(client, redirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	// 5. Validate scope (must be subset of client's allowed scopes)
	if scope != "" && !s.isValidScope(client.Scopes, scope) {
		return nil, ErrInvalidAuthCodeScope
	}
	if scope == "" {
		scope = client.Scopes // Default to all client scopes
	}

	// 6. PKCE: public clients must use S256
	if client.ClientType == "public" {
		if codeChallengeMethod == "" {
			return nil, ErrPKCERequired
		}
	}
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" &&
		codeChallengeMethod != "plain" {
		return nil, ErrInvalidAuthCodeRequest
	}
	// Global PKCE enforcement
	if s.config.PKCERequired && codeChallengeMethod == "" {
		return nil, ErrPKCERequired
	}

	return &AuthorizationRequest{
		Client:              client,
		RedirectURI:         redirectURI,
		Scopes:              scope,
		CodeChallengeMethod: codeChallengeMethod,
	}, nil
}

// CreateAuthorizationCode generates a one-time authorization code and saves it to the database.
// Returns the plaintext code (to be sent in the redirect) and the stored record.
func (s *AuthorizationService) CreateAuthorizationCode(
	ctx context.Context,
	applicationID int64,
	clientID, userID, redirectURI, scopes, codeChallenge, codeChallengeMethod string,
) (plainCode string, record *models.AuthorizationCode, err error) {
	// Generate 32 cryptographically random bytes (256-bit entropy)
	rawBytes, err := util.CryptoRandomBytes(32)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}
	plainCode = hex.EncodeToString(rawBytes) // 64-char hex string

	// SHA-256 hash for secure storage (no salt needed: 256-bit entropy is sufficient)
	sum := sha256.Sum256([]byte(plainCode))
	codeHash := hex.EncodeToString(sum[:])
	codePrefix := plainCode[:8]

	record = &models.AuthorizationCode{
		UUID:                uuid.New().String(),
		CodeHash:            codeHash,
		CodePrefix:          codePrefix,
		ApplicationID:       applicationID,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.config.AuthCodeExpiration),
	}

	if err := s.store.CreateAuthorizationCode(record); err != nil {
		return "", nil, fmt.Errorf("failed to save authorization code: %w", err)
	}

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventAuthorizationCodeGenerated,
			Severity:     models.SeverityInfo,
			ActorUserID:  userID,
			ResourceType: models.ResourceAuthorization,
			ResourceID:   record.UUID,
			Action:       "Authorization code generated",
			Details: models.AuditDetails{
				"client_id":    clientID,
				"scopes":       scopes,
				"pkce":         codeChallenge != "",
				"redirect_uri": redirectURI,
			},
			Success: true,
		})
	}

	return plainCode, record, nil
}

// ExchangeCode validates a plaintext authorization code and marks it as used.
// The caller (TokenHandler) is responsible for issuing tokens after this returns successfully.
func (s *AuthorizationService) ExchangeCode(
	ctx context.Context,
	plainCode, clientID, redirectURI, clientSecret, codeVerifier string,
) (*models.AuthorizationCode, error) {
	// Hash the incoming code for lookup
	sum := sha256.Sum256([]byte(plainCode))
	codeHash := hex.EncodeToString(sum[:])

	record, err := s.store.GetAuthorizationCodeByHash(codeHash)
	if err != nil {
		return nil, ErrAuthCodeNotFound
	}

	// Validate state
	if record.IsUsed() {
		return nil, ErrAuthCodeAlreadyUsed
	}
	if record.IsExpired() {
		return nil, ErrAuthCodeExpired
	}
	if record.ClientID != clientID {
		return nil, ErrAuthCodeNotFound // Don't reveal the code exists for another client
	}
	if record.RedirectURI != redirectURI {
		return nil, ErrInvalidRedirectURI
	}

	// Client authentication
	client, err := s.store.GetClient(clientID)
	if err != nil || !client.IsActive {
		return nil, ErrUnauthorizedClient
	}

	if client.ClientType == "confidential" {
		// Confidential clients must present their secret
		if clientSecret == "" {
			return nil, ErrUnauthorizedClient
		}
		if !verifyClientSecret(client.ClientSecret, clientSecret) {
			return nil, ErrUnauthorizedClient
		}
	} else {
		// Public clients must present PKCE code_verifier
		if record.CodeChallenge == "" {
			return nil, ErrPKCERequired
		}
		if !verifyPKCE(record.CodeChallenge, record.CodeChallengeMethod, codeVerifier) {
			return nil, ErrInvalidCodeVerifier
		}
	}

	// Mark as used atomically (WHERE used_at IS NULL ensures only one concurrent
	// request wins; the loser receives ErrAuthCodeAlreadyUsed from the store).
	now := time.Now()
	if err := s.store.MarkAuthorizationCodeUsed(record.ID); err != nil {
		if errors.Is(err, store.ErrAuthCodeAlreadyUsed) {
			return nil, ErrAuthCodeAlreadyUsed
		}
		return nil, fmt.Errorf("failed to mark code as used: %w", err)
	}
	record.UsedAt = &now // Reflect DB state in the returned struct

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventAuthorizationCodeExchanged,
			Severity:     models.SeverityInfo,
			ActorUserID:  record.UserID,
			ResourceType: models.ResourceAuthorization,
			ResourceID:   record.UUID,
			Action:       "Authorization code exchanged for token",
			Details: models.AuditDetails{
				"client_id": clientID,
				"scopes":    record.Scopes,
			},
			Success: true,
		})
	}

	return record, nil
}

// GetUserAuthorization returns the active consent record for a (user, application) pair.
// Returns nil, nil when no consent exists (not an error condition).
func (s *AuthorizationService) GetUserAuthorization(
	userID string,
	applicationID int64,
) (*models.UserAuthorization, error) {
	auth, err := s.store.GetUserAuthorization(userID, applicationID)
	if err != nil {
		return nil, nil // Treat as "not found" for consent check
	}
	return auth, nil
}

// SaveUserAuthorization creates or updates the consent record for a user+application pair.
func (s *AuthorizationService) SaveUserAuthorization(
	ctx context.Context,
	userID string,
	applicationID int64,
	clientID, scopes string,
) (*models.UserAuthorization, error) {
	auth := &models.UserAuthorization{
		UUID:          uuid.New().String(),
		UserID:        userID,
		ApplicationID: applicationID,
		ClientID:      clientID,
		Scopes:        scopes,
		GrantedAt:     time.Now(),
		IsActive:      true,
	}

	if err := s.store.UpsertUserAuthorization(auth); err != nil {
		return nil, fmt.Errorf("failed to save user authorization: %w", err)
	}

	// Re-fetch to get the stored record (UpsertUserAuthorization may modify in-place)
	stored, err := s.store.GetUserAuthorization(userID, applicationID)
	if err != nil {
		return auth, nil // Return what we built; non-fatal
	}

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventUserAuthorizationGranted,
			Severity:     models.SeverityInfo,
			ActorUserID:  userID,
			ResourceType: models.ResourceAuthorization,
			ResourceID:   stored.UUID,
			Action:       "User granted authorization to application",
			Details: models.AuditDetails{
				"client_id": clientID,
				"scopes":    scopes,
			},
			Success: true,
		})
	}

	return stored, nil
}

// RevokeUserAuthorization revokes a user's consent for an application.
// It also revokes all active tokens that were issued under this authorization.
func (s *AuthorizationService) RevokeUserAuthorization(
	ctx context.Context,
	authUUID, userID string,
) error {
	revoked, err := s.store.RevokeUserAuthorization(authUUID, userID)
	if err != nil {
		return ErrAuthorizationNotFound
	}

	// Cascade-revoke all tokens tied to this authorization
	_ = s.store.RevokeTokensByAuthorizationID(revoked.ID)

	if s.auditService != nil {
		s.auditService.Log(ctx, AuditLogEntry{
			EventType:    models.EventUserAuthorizationRevoked,
			Severity:     models.SeverityInfo,
			ActorUserID:  userID,
			ResourceType: models.ResourceAuthorization,
			ResourceID:   authUUID,
			Action:       "User revoked authorization for application",
			Details: models.AuditDetails{
				"client_id": revoked.ClientID,
				"scopes":    revoked.Scopes,
			},
			Success: true,
		})
	}

	return nil
}

// ListUserAuthorizations returns all active authorizations for a user with client display names.
func (s *AuthorizationService) ListUserAuthorizations(
	ctx context.Context,
	userID string,
) ([]UserAuthorizationWithClient, error) {
	auths, err := s.store.ListUserAuthorizations(userID)
	if err != nil {
		return nil, err
	}
	if len(auths) == 0 {
		return []UserAuthorizationWithClient{}, nil
	}

	// Batch-fetch client names
	clientIDs := make([]string, 0, len(auths))
	seen := make(map[string]bool)
	for _, a := range auths {
		if !seen[a.ClientID] {
			clientIDs = append(clientIDs, a.ClientID)
			seen[a.ClientID] = true
		}
	}
	clientMap, _ := s.store.GetClientsByIDs(clientIDs)

	result := make([]UserAuthorizationWithClient, 0, len(auths))
	for _, a := range auths {
		clientName := a.ClientID
		if c, ok := clientMap[a.ClientID]; ok && c != nil {
			clientName = c.ClientName
		}
		result = append(result, UserAuthorizationWithClient{
			UserAuthorization: a,
			ClientName:        clientName,
		})
	}

	return result, nil
}

// RevokeAllApplicationTokens revokes all active tokens and consent records for an application.
// This is an admin operation that forces all users to re-authenticate.
func (s *AuthorizationService) RevokeAllApplicationTokens(
	ctx context.Context,
	clientID, actorUserID string,
) (int64, error) {
	// Revoke all active tokens
	revokedCount, err := s.store.RevokeAllActiveTokensByClientID(clientID)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke tokens: %w", err)
	}

	// Invalidate all consent records so users see the consent page again
	_ = s.store.RevokeAllUserAuthorizationsByClientID(clientID)

	if s.auditService != nil {
		_ = s.auditService.LogSync(ctx, AuditLogEntry{
			EventType:    models.EventClientTokensRevokedAll,
			Severity:     models.SeverityCritical,
			ActorUserID:  actorUserID,
			ResourceType: models.ResourceClient,
			ResourceID:   clientID,
			Action:       "All client tokens revoked by administrator",
			Details: models.AuditDetails{
				"client_id":     clientID,
				"revoked_count": revokedCount,
			},
			Success: true,
		})
	}

	return revokedCount, nil
}

// UserAuthorizationWithClient combines a UserAuthorization with its client's display name
type UserAuthorizationWithClient struct {
	models.UserAuthorization
	ClientName string
}

// UserAuthorizationWithUser combines a UserAuthorization with the authorizing user's details
type UserAuthorizationWithUser struct {
	models.UserAuthorization
	Username string
	Email    string
}

// ListClientAuthorizations returns all active consent grants for a given client, with user details.
// Intended for the admin overview page.
func (s *AuthorizationService) ListClientAuthorizations(
	ctx context.Context,
	clientID string,
) ([]UserAuthorizationWithUser, error) {
	auths, err := s.store.GetClientAuthorizations(clientID)
	if err != nil {
		return nil, err
	}
	if len(auths) == 0 {
		return []UserAuthorizationWithUser{}, nil
	}

	// Batch-fetch user display names
	userIDSet := make(map[string]bool)
	for _, a := range auths {
		userIDSet[a.UserID] = true
	}
	userIDs := make([]string, 0, len(userIDSet))
	for id := range userIDSet {
		userIDs = append(userIDs, id)
	}
	userMap, _ := s.store.GetUsersByIDs(userIDs)

	result := make([]UserAuthorizationWithUser, 0, len(auths))
	for _, a := range auths {
		username, email := a.UserID, ""
		if u, ok := userMap[a.UserID]; ok && u != nil {
			username = u.Username
			email = u.Email
		}
		result = append(result, UserAuthorizationWithUser{
			UserAuthorization: a,
			Username:          username,
			Email:             email,
		})
	}
	return result, nil
}

// ============================================================
// PKCE helpers (RFC 7636)
// ============================================================

// verifyPKCE validates code_verifier against the stored code_challenge
func verifyPKCE(codeChallenge, method, codeVerifier string) bool {
	if codeVerifier == "" {
		return false
	}
	switch strings.ToUpper(method) {
	case "S256":
		sum := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		return computed == codeChallenge
	case "PLAIN", "":
		return codeVerifier == codeChallenge
	default:
		return false
	}
}

// ============================================================
// Client secret verification
// ============================================================

// verifyClientSecret performs bcrypt comparison of the stored hashed client secret.
func verifyClientSecret(hashedSecret, plainSecret string) bool {
	if len(hashedSecret) == 0 || len(plainSecret) == 0 {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(plainSecret))
	return err == nil
}

// ============================================================
// Scope helpers
// ============================================================

func (s *AuthorizationService) isValidRedirectURI(
	client *models.OAuthApplication,
	uri string,
) bool {
	if uri == "" {
		return false
	}
	for _, registered := range client.RedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

func (s *AuthorizationService) isValidScope(clientScopes, requestedScopes string) bool {
	allowed := make(map[string]bool)
	for _, sc := range strings.Fields(clientScopes) {
		allowed[sc] = true
	}
	for _, sc := range strings.Fields(requestedScopes) {
		if !allowed[sc] {
			return false
		}
	}
	return true
}
