package services

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
)

// TokenWithClient combines token and client information for display
type TokenWithClient struct {
	models.AccessToken
	ClientName string
}

var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
	ErrTokenCannotDisable   = errors.New(
		"token cannot be disabled: only active tokens can be disabled",
	)
	ErrTokenCannotEnable = errors.New(
		"token cannot be enabled: only disabled tokens can be re-enabled",
	)

	// Client Credentials Flow errors (RFC 6749 §4.4)
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrClientNotConfidential    = errors.New(
		"client_credentials grant requires a confidential client",
	)
	ErrClientCredentialsFlowDisabled = errors.New(
		"client_credentials flow is not enabled for this client",
	)
)

type TokenService struct {
	store         core.Store
	config        *config.Config
	deviceService *DeviceService
	tokenProvider core.TokenProvider
	auditService  core.AuditLogger
	metrics       core.Recorder
	tokenCache    core.Cache[models.AccessToken]
	clientService *ClientService
}

func NewTokenService(
	s core.Store,
	cfg *config.Config,
	ds *DeviceService,
	provider core.TokenProvider,
	auditService core.AuditLogger,
	m core.Recorder,
	tokenCache core.Cache[models.AccessToken],
	clientService *ClientService,
) *TokenService {
	if auditService == nil {
		auditService = NewNoopAuditService()
	}
	return &TokenService{
		store:         s,
		config:        cfg,
		deviceService: ds,
		tokenProvider: provider,
		auditService:  auditService,
		metrics:       m,
		tokenCache:    tokenCache,
		clientService: clientService,
	}
}

// resolveUsername looks up the username for a given userID.
// Returns empty string on error (best-effort for audit logging).
func (s *TokenService) resolveUsername(userID string) string {
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		return ""
	}
	return user.Username
}

// getAccessTokenByHash looks up a token, using cache if available.
// On cache backend errors (e.g. Redis unavailable), falls back to direct DB lookup
// so that valid tokens are not rejected due to cache infrastructure issues.
func (s *TokenService) getAccessTokenByHash(
	ctx context.Context,
	hash string,
) (*models.AccessToken, error) {
	tok, err := s.tokenCache.GetWithFetch(ctx, hash, s.config.TokenCacheTTL,
		func(ctx context.Context, _ string) (models.AccessToken, error) {
			t, storeErr := s.store.GetAccessTokenByHash(hash)
			if storeErr != nil {
				return models.AccessToken{}, &fetchErr{cause: storeErr}
			}
			return *t, nil
		},
	)
	if err == nil {
		return &tok, nil
	}
	// Store error from fetchFunc — the DB was reached, no need to retry.
	var fe *fetchErr
	if errors.As(err, &fe) {
		return nil, fe.cause
	}
	// Corrupted cache entry — delete it so the next request re-populates it.
	if errors.Is(err, cache.ErrInvalidValue) {
		if delErr := s.tokenCache.Delete(ctx, hash); delErr != nil {
			hashPrefix := hash
			if len(hashPrefix) > 8 {
				hashPrefix = hashPrefix[:8]
			}
			log.Printf(
				"[TokenCache] Failed to evict corrupted entry for hash=%s...: %v",
				hashPrefix,
				delErr,
			)
		}
	}
	log.Printf("[TokenCache] cache lookup failed, falling back to DB: %v", err)
	return s.store.GetAccessTokenByHash(hash)
}

// invalidateTokenCache removes a token from cache by its hash.
func (s *TokenService) invalidateTokenCache(ctx context.Context, hash string) {
	if err := s.tokenCache.Delete(ctx, hash); err != nil {
		hashPrefix := hash
		if len(hashPrefix) > 8 {
			hashPrefix = hashPrefix[:8]
		}
		log.Printf(
			"[TokenCache] failed to invalidate cache for hash=%s...: %v",
			hashPrefix, err,
		)
	}
}

// invalidateTokenCacheByHashes removes multiple tokens from cache.
func (s *TokenService) invalidateTokenCacheByHashes(ctx context.Context, hashes []string) {
	for _, h := range hashes {
		s.invalidateTokenCache(ctx, h)
	}
}

// InvalidateTokenCacheByHashes removes multiple tokens from cache by their hashes.
// Exported for use by other services (e.g., AuthorizationService) during bulk revocation.
func (s *TokenService) InvalidateTokenCacheByHashes(ctx context.Context, hashes []string) {
	s.invalidateTokenCacheByHashes(ctx, hashes)
}

// tokenPairParams holds the inputs for creating an access + refresh token pair.
type tokenPairParams struct {
	UserID          string
	ClientID        string
	Scopes          string
	AuthorizationID *uint // nil when not linked to a UserAuthorization (e.g. device flow)
}

// generateAndPersistTokenPair generates access and refresh tokens via the
// configured provider, builds database records, and persists them atomically.
func (s *TokenService) generateAndPersistTokenPair(
	ctx context.Context,
	p tokenPairParams,
) (*models.AccessToken, *models.AccessToken, error) {
	// Generate tokens via provider
	accessResult, err := s.tokenProvider.GenerateToken(ctx, p.UserID, p.ClientID, p.Scopes)
	if err != nil {
		log.Printf(
			"[Token] Access token generation failed provider=%s: %v",
			s.tokenProvider.Name(),
			err,
		)
		return nil, nil, fmt.Errorf("token generation failed: %w", err)
	}
	refreshResult, err := s.tokenProvider.GenerateRefreshToken(ctx, p.UserID, p.ClientID, p.Scopes)
	if err != nil {
		log.Printf(
			"[Token] Refresh token generation failed provider=%s: %v",
			s.tokenProvider.Name(),
			err,
		)
		return nil, nil, fmt.Errorf("refresh token generation failed: %w", err)
	}

	// Build token records
	accessToken := &models.AccessToken{
		ID:              uuid.New().String(),
		TokenHash:       util.SHA256Hex(accessResult.TokenString),
		RawToken:        accessResult.TokenString,
		TokenType:       accessResult.TokenType,
		TokenCategory:   models.TokenCategoryAccess,
		Status:          models.TokenStatusActive,
		UserID:          p.UserID,
		ClientID:        p.ClientID,
		Scopes:          p.Scopes,
		ExpiresAt:       accessResult.ExpiresAt,
		AuthorizationID: p.AuthorizationID,
	}

	refreshTokenID := uuid.New().String()
	refreshToken := &models.AccessToken{
		ID:              refreshTokenID,
		TokenHash:       util.SHA256Hex(refreshResult.TokenString),
		RawToken:        refreshResult.TokenString,
		TokenType:       refreshResult.TokenType,
		TokenCategory:   models.TokenCategoryRefresh,
		Status:          models.TokenStatusActive,
		UserID:          p.UserID,
		ClientID:        p.ClientID,
		Scopes:          p.Scopes,
		ExpiresAt:       refreshResult.ExpiresAt,
		AuthorizationID: p.AuthorizationID,
	}

	// In rotation mode, set TokenFamilyID to the refresh token's own ID (family root)
	if s.config.EnableTokenRotation {
		refreshToken.TokenFamilyID = refreshTokenID
		accessToken.TokenFamilyID = refreshTokenID
	}

	// Persist both tokens atomically
	if err := s.store.RunInTransaction(func(tx core.Store) error {
		if err := tx.CreateAccessToken(accessToken); err != nil {
			return fmt.Errorf("failed to save access token: %w", err)
		}
		if err := tx.CreateAccessToken(refreshToken); err != nil {
			return fmt.Errorf("failed to save refresh token: %w", err)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}
