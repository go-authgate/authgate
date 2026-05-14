package services

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
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
	ErrInvalidTarget           = errors.New("invalid_target")
)

// AuthorizationRequest holds validated parameters for an authorization request
type AuthorizationRequest struct {
	Client              *models.OAuthApplication
	RedirectURI         string
	Scopes              string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	// Resource holds validated RFC 8707 Resource Indicator values requested
	// at /authorize. Empty means the caller did not request a specific
	// audience.
	Resource []string
}

// AuthorizationService manages the OAuth 2.0 Authorization Code Flow (RFC 6749)
type AuthorizationService struct {
	store         core.Store
	config        *config.Config
	auditService  core.AuditLogger
	tokenService  *TokenService
	clientService *ClientService
}

func NewAuthorizationService(
	s core.Store,
	cfg *config.Config,
	auditService core.AuditLogger,
	tokenService *TokenService,
	clientService *ClientService,
) *AuthorizationService {
	if auditService == nil {
		auditService = NewNoopAuditService()
	}
	return &AuthorizationService{
		store:         s,
		config:        cfg,
		auditService:  auditService,
		tokenService:  tokenService,
		clientService: clientService,
	}
}

// ValidateAuthorizationRequest validates all parameters of an incoming authorization request.
// Returns the parsed AuthorizationRequest on success.
// `resource` carries the already-validated RFC 8707 Resource Indicator values
// (pass nil/empty when none were supplied).
func (s *AuthorizationService) ValidateAuthorizationRequest(
	ctx context.Context,
	clientID, redirectURI, responseType, scope, codeChallenge, codeChallengeMethod, nonce string,
	resource []string,
) (*AuthorizationRequest, error) {
	// 1. response_type must be "code"
	if responseType != "code" {
		return nil, ErrUnsupportedResponseType
	}

	// 2. Client must exist and be active
	client, err := s.clientService.GetClient(ctx, clientID)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}
	if !client.IsActive() {
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
	if scope != "" && !util.IsScopeSubset(client.Scopes, scope) {
		return nil, ErrInvalidAuthCodeScope
	}
	if scope == "" {
		scope = client.Scopes // Default to all client scopes
	}

	// 6. PKCE: public clients must use S256
	if core.ClientType(client.ClientType) == core.ClientTypePublic {
		if codeChallengeMethod == "" {
			return nil, ErrPKCERequired
		}
	}
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
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
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		Resource:            resource,
	}, nil
}

// CreateAuthorizationCodeParams bundles the inputs for authorization code creation.
type CreateAuthorizationCodeParams struct {
	ApplicationID       int64
	ClientID            string
	UserID              string
	RedirectURI         string
	Scopes              string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	// Resource holds RFC 8707 Resource Indicator values to persist on the
	// authorization code so the /token grant can bind them to the issued
	// JWT's "aud" claim. Empty means no resource was requested.
	Resource []string
}

// CreateAuthorizationCode generates a one-time authorization code and saves it to the database.
// Returns the plaintext code (to be sent in the redirect) and the stored record.
func (s *AuthorizationService) CreateAuthorizationCode(
	ctx context.Context,
	params CreateAuthorizationCodeParams,
) (plainCode string, record *models.AuthorizationCode, err error) {
	// Generate 32 cryptographically random bytes (256-bit entropy)
	rawBytes, err := util.CryptoRandomBytes(32)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}
	plainCode = hex.EncodeToString(rawBytes) // 64-char hex string

	// SHA-256 hash for secure storage (no salt needed: 256-bit entropy is sufficient)
	codeHash := util.SHA256Hex(plainCode)
	codePrefix := plainCode[:8]

	record = &models.AuthorizationCode{
		UUID:                uuid.New().String(),
		CodeHash:            codeHash,
		CodePrefix:          codePrefix,
		ApplicationID:       params.ApplicationID,
		ClientID:            params.ClientID,
		UserID:              params.UserID,
		RedirectURI:         params.RedirectURI,
		Scopes:              params.Scopes,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Nonce:               params.Nonce,
		Resource:            models.StringArray(params.Resource),
		ExpiresAt:           time.Now().Add(s.config.AuthCodeExpiration),
	}

	if err := s.store.CreateAuthorizationCode(record); err != nil {
		return "", nil, fmt.Errorf("failed to save authorization code: %w", err)
	}

	details := models.AuditDetails{
		"client_id":    params.ClientID,
		"scopes":       params.Scopes,
		"pkce":         params.CodeChallenge != "",
		"redirect_uri": params.RedirectURI,
	}
	if len(params.Resource) > 0 {
		details["resource"] = params.Resource
	}
	s.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventAuthorizationCodeGenerated,
		Severity:     models.SeverityInfo,
		ActorUserID:  params.UserID,
		ResourceType: models.ResourceAuthorization,
		ResourceID:   record.UUID,
		Action:       "Authorization code generated",
		Details:      details,
		Success:      true,
	})

	return plainCode, record, nil
}

// ExchangeCode validates a plaintext authorization code and marks it as used.
// The caller (TokenHandler) is responsible for issuing tokens after this returns successfully.
func (s *AuthorizationService) ExchangeCode(
	ctx context.Context,
	plainCode, clientID, redirectURI, clientSecret, codeVerifier string,
) (*models.AuthorizationCode, error) {
	// Hash the incoming code for lookup
	codeHash := util.SHA256Hex(plainCode)

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

	// Client authentication (needs secret for confidential clients)
	client, err := s.clientService.GetClientWithSecret(ctx, clientID)
	if err != nil {
		return nil, ErrUnauthorizedClient
	}
	if !client.IsActive() {
		return nil, ErrUnauthorizedClient
	}

	if core.ClientType(client.ClientType) == core.ClientTypeConfidential {
		// Confidential clients must present their secret
		if clientSecret == "" {
			return nil, ErrUnauthorizedClient
		}
		if !client.ValidateClientSecret([]byte(clientSecret)) {
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

	s.auditService.Log(ctx, core.AuditLogEntry{
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
		return nil, nil //nolint:nilnil // nil UserAuthorization means "not found", which is not an error
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

	s.auditService.Log(ctx, core.AuditLogEntry{
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

	hashes, err := s.store.GetActiveTokenHashesByAuthorizationID(revoked.ID)
	if err != nil {
		log.Printf(
			"[TokenCache] WARNING: failed to collect token hashes for authorization=%d, "+
				"revoked tokens may remain cached until TTL expires: %v",
			revoked.ID,
			err,
		)
	}

	// Cascade-revoke all tokens tied to this authorization
	if revokeErr := s.store.RevokeTokensByAuthorizationID(revoked.ID); revokeErr != nil {
		log.Printf(
			"[Authorization] failed to revoke tokens for authorization=%d: %v",
			revoked.ID,
			revokeErr,
		)
	}

	if len(hashes) > 0 && s.tokenService != nil {
		s.tokenService.InvalidateTokenCacheByHashes(ctx, hashes)
	}

	s.auditService.Log(ctx, core.AuditLogEntry{
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
	clientIDs := util.UniqueKeys(
		auths,
		func(a models.UserAuthorization) string { return a.ClientID },
	)
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
	hashes, err := s.store.GetActiveTokenHashesByClientID(clientID)
	if err != nil {
		log.Printf(
			"[TokenCache] WARNING: failed to collect token hashes for client=%s, "+
				"revoked tokens may remain cached until TTL expires: %v",
			clientID, err,
		)
	}

	revokedCount, err := s.store.RevokeAllActiveTokensByClientID(clientID)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke tokens: %w", err)
	}

	if len(hashes) > 0 && s.tokenService != nil {
		s.tokenService.InvalidateTokenCacheByHashes(ctx, hashes)
	}

	// Invalidate all consent records so users see the consent page again
	_ = s.store.RevokeAllUserAuthorizationsByClientID(clientID)

	_ = s.auditService.LogSync(ctx, core.AuditLogEntry{
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
	userIDs := util.UniqueKeys(auths, func(a models.UserAuthorization) string { return a.UserID })
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
		return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
	case "":
		return subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(codeChallenge)) == 1
	default:
		return false
	}
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
	return slices.Contains([]string(client.RedirectURIs), uri)
}
