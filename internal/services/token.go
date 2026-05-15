package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/token"
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
	// privateClaimPrefix is cfg.JWTPrivateClaimPrefix normalized at
	// construction time so that ad-hoc test configs that build Config{}
	// directly (without going through Load()) get production-equivalent
	// claim composition. Mirrors the same defaulting NewExtraClaimsParser
	// and NewLocalTokenProvider apply, ensuring every layer sees the same
	// prefix.
	privateClaimPrefix string
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
	prefix := cfg.JWTPrivateClaimPrefix
	if prefix == "" {
		prefix = config.DefaultJWTPrivateClaimPrefix
	}
	return &TokenService{
		store:              s,
		config:             cfg,
		deviceService:      ds,
		tokenProvider:      provider,
		auditService:       auditService,
		metrics:            m,
		tokenCache:         tokenCache,
		clientService:      clientService,
		privateClaimPrefix: prefix,
	}
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
	// Client is the already-loaded OAuth client, used to resolve the
	// TokenProfile TTLs without an extra cached lookup. Both issuance callers
	// (device flow, auth-code flow) load the client up front for other
	// validation, so this is always populated.
	Client *models.OAuthApplication
	// ExtraClaims carries caller-supplied JWT claims parsed from the
	// extra_claims form parameter. Reserved keys are rejected by the parser
	// and overridden by generateJWT; system claims (project, service_account)
	// from buildClientClaims are merged on top of these so admins always win.
	ExtraClaims map[string]any
	// Resource holds RFC 8707 Resource Indicator values to bind into the
	// access token's "aud" claim. Empty means fall back to the static
	// JWTAudience config. Persisted on the access token row.
	Resource []string
	// RefreshResource overrides what gets persisted on the refresh-token row's
	// `Resource` column — it does NOT affect the refresh JWT's `aud` claim
	// (the refresh token is always signed with nil audience override; see
	// generateAndPersistTokenPair). Used by issuance flows that narrow the
	// access token (auth-code, device-code) to record the FULL granted
	// resource set on the refresh row so future RFC 8707 §2.2 subset checks
	// re-narrow against the original grant rather than the already-narrowed
	// access-token audience. When nil, the refresh row falls back to Resource.
	RefreshResource []string
}

// ttlForClient returns the access/refresh TTLs dictated by the given client's
// TokenProfile. Zero means "fall back to provider default" — returned when the
// profile's TTL matches the base JWT/refresh config so that the local provider
// still applies JWT_EXPIRATION_JITTER on the common path. Explicit short/long
// overrides (and a standard profile diverged from base config) return the
// profile's TTL exactly, no jitter.
//
// An unknown profile name on the client row is a data-integrity issue (GORM
// default + admin UI should prevent it). We log a WARNING so the bad row can
// be traced and fall back to the standard profile's TTLs; that's more
// conservative than returning zero, which would silently grant base JWT
// lifetime to a client the admin intended to restrict.
func (s *TokenService) ttlForClient(
	client *models.OAuthApplication,
) (accessTTL, refreshTTL time.Duration) {
	if client == nil {
		return 0, 0
	}
	name := models.ResolveTokenProfile(client.TokenProfile)
	profile, ok := s.config.TokenProfiles[name]
	if !ok {
		log.Printf(
			"[Token] client %s has unknown token_profile=%q; falling back to standard",
			client.ClientID,
			client.TokenProfile,
		)
		name = models.TokenProfileStandard
		profile, ok = s.config.TokenProfiles[name]
		if !ok {
			return 0, 0
		}
	}
	accessTTL = profile.AccessTokenTTL
	refreshTTL = profile.RefreshTokenTTL
	// Only the standard profile zeroes out to let jitter apply. Short/long are
	// explicit admin choices and must use their TTLs exactly, even if they
	// coincidentally match the base JWT config.
	if name == models.TokenProfileStandard {
		if accessTTL == s.config.JWTExpiration {
			accessTTL = 0
		}
		if refreshTTL == s.config.RefreshTokenExpiration {
			refreshTTL = 0
		}
	}
	return accessTTL, refreshTTL
}

// resolveClientTTL fetches the client by ID and returns its profile TTLs.
// Use ttlForClient directly when the caller already has the client loaded.
func (s *TokenService) resolveClientTTL(
	ctx context.Context,
	clientID string,
) (accessTTL, refreshTTL time.Duration) {
	if s.clientService == nil {
		return 0, 0
	}
	client, err := s.clientService.GetClient(ctx, clientID)
	if err != nil {
		return 0, 0
	}
	return s.ttlForClient(client)
}

// buildClientClaims returns the JWT extra claims sourced from the OAuth
// application: project and service_account, emitted under the configured
// private-claim prefix (e.g. "extra_project", "extra_service_account" with
// the default prefix "extra"). Empty fields are omitted so we never write
// meaningless empty-string claims into the JWT, and the map is only
// allocated when at least one field has a value — this is on the token
// issuance hot path and most clients won't set either field.
func buildClientClaims(client *models.OAuthApplication, prefix string) map[string]any {
	if client == nil || (client.Project == "" && client.ServiceAccount == "") {
		return nil
	}
	claims := make(map[string]any, 2)
	if client.Project != "" {
		claims[token.EmittedName(prefix, "project")] = client.Project
	}
	if client.ServiceAccount != "" {
		claims[token.EmittedName(prefix, "service_account")] = client.ServiceAccount
	}
	return claims
}

// mergeCallerExtraClaims merges caller-supplied claims into a base map of
// system-managed claims. Caller values are written first so the system map
// (project, service_account from buildClientClaims) overrides on collision —
// admins always win over caller self-assertions.
func mergeCallerExtraClaims(system, caller map[string]any) map[string]any {
	if len(caller) == 0 {
		return system
	}
	out := make(map[string]any, len(caller)+len(system))
	maps.Copy(out, caller)
	maps.Copy(out, system)
	return out
}

// buildServerClaims returns the JWT claims sourced from server-attested state
// (`<prefix>_domain` from JWT_DOMAIN, `<prefix>_uid` from User.Username),
// emitted under the supplied (already-normalized) prefix. Each source is
// independently optional; empty inputs are omitted. See token/types.go for
// trust-model details.
func buildServerClaims(domain, username, prefix string) map[string]any {
	if domain == "" && username == "" {
		return nil
	}
	out := make(map[string]any, 2)
	if domain != "" {
		out[token.EmittedName(prefix, "domain")] = domain
	}
	if username != "" {
		out[token.EmittedName(prefix, "uid")] = username
	}
	return out
}

// applyServerClaims overlays server-attested claims onto an already-merged
// caller+client map. Server values win on collision so the deployment-level
// invariant cannot be shadowed by caller extra_claims or per-client metadata.
// claims must be owned by the caller — applyServerClaims may mutate it in
// place. mergeCallerExtraClaims returns a freshly-allocated map when caller
// claims are non-empty, and buildClientClaims always allocates fresh, so the
// existing call sites already satisfy this.
func applyServerClaims(claims, server map[string]any) map[string]any {
	if len(server) == 0 {
		return claims
	}
	if claims == nil {
		claims = make(map[string]any, len(server))
	}
	maps.Copy(claims, server)
	return claims
}

// resolveUsernameForUID returns the User.Username to emit as `<prefix>_uid`,
// or "" to omit the claim. Returns "" for empty / machine UserIDs and on
// store-lookup failure (logged so the silent omission is diagnosable);
// issuance never fails on a missing user.
func (s *TokenService) resolveUsernameForUID(userID string) string {
	if userID == "" || IsMachineUserID(userID) {
		return ""
	}
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		log.Printf("[Token] uid claim: GetUserByID failed user_id=%s: %v", userID, err)
		return ""
	}
	return user.Username
}

// composeIssuanceClaims builds the merged claim map handed to the token
// provider on every issuance path (auth_code, device_code, client_credentials,
// refresh). Precedence is caller → client → server, with server writing last
// so server-attested claims cannot be shadowed by caller-supplied extra_claims.
func (s *TokenService) composeIssuanceClaims(
	client *models.OAuthApplication,
	userID string,
	caller map[string]any,
) map[string]any {
	prefix := s.privateClaimPrefix
	username := s.resolveUsernameForUID(userID)
	claims := mergeCallerExtraClaims(buildClientClaims(client, prefix), caller)
	return applyServerClaims(claims, buildServerClaims(s.config.JWTDomain, username, prefix))
}

// generateAndPersistTokenPair generates access and refresh tokens via the
// configured provider, builds database records, and persists them atomically.
// The per-client TokenProfile is resolved here so that all issuance paths
// (device flow, auth code flow) honor the current profile at issuance time.
func (s *TokenService) generateAndPersistTokenPair(
	ctx context.Context,
	p tokenPairParams,
) (*models.AccessToken, *models.AccessToken, error) {
	var (
		accessTTL, refreshTTL time.Duration
		extraClaims           map[string]any
	)
	client := p.Client
	if client == nil && s.clientService != nil {
		// Defensive fallback — issuance callers normally populate p.Client.
		// One lookup serves both the TTL profile and the JWT extra claims.
		c, err := s.clientService.GetClient(ctx, p.ClientID)
		if err != nil {
			// p.Client unset is already an unexpected state for issuance; log
			// the lookup failure so a missing TokenProfile / project /
			// service_account on the issued token is diagnosable rather than
			// silent.
			log.Printf(
				"[Token] Issuance client lookup failed, falling back to defaults client_id=%s: %v",
				p.ClientID, err,
			)
		} else {
			client = c
		}
	}
	if client != nil {
		accessTTL, refreshTTL = s.ttlForClient(client)
	}
	extraClaims = s.composeIssuanceClaims(client, p.UserID, p.ExtraClaims)

	accessResult, err := s.tokenProvider.GenerateToken(
		ctx, p.UserID, p.ClientID, p.Scopes, accessTTL, extraClaims, p.Resource,
	)
	if err != nil {
		log.Printf(
			"[Token] Access token generation failed provider=%s: %v",
			s.tokenProvider.Name(),
			err,
		)
		return nil, nil, fmt.Errorf("token generation failed: %w", err)
	}
	// Refresh tokens never carry the per-request RFC 8707 resource as `aud` —
	// they're presented to the AS, not the RS. Pass nil so the JWT audience
	// falls back to the static JWTAudience config (deployments must point
	// `JWT_AUDIENCE` at an AS-only value or leave it unset; see
	// core/token.go on RefreshAccessToken for why). The persisted Resource
	// column on the refresh-token row still records the granted resource
	// set, so future refresh requests can subset-check against it.
	refreshResult, err := s.tokenProvider.GenerateRefreshToken(
		ctx, p.UserID, p.ClientID, p.Scopes, refreshTTL, extraClaims, nil,
	)
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
		Resource:        models.StringArray(p.Resource),
	}

	// Persisted Resource on the refresh-token row drives RFC 8707 §2.2
	// subset checks on subsequent refresh requests. When the caller wants
	// the refresh token to remember the FULL grant (not the narrowed access
	// audience), p.RefreshResource is passed; otherwise it falls back to
	// p.Resource so non-narrowing flows keep working.
	refreshDBResource := p.RefreshResource
	if refreshDBResource == nil {
		refreshDBResource = p.Resource
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
		Resource:        models.StringArray(refreshDBResource),
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
