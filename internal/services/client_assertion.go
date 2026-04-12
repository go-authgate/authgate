package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/golang-jwt/jwt/v5"
)

// AssertionType is the sole value allowed for the client_assertion_type parameter
// when using JWT Bearer Assertions (RFC 7523 §2.2).
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// jtiCacheKeyPrefix namespaces the per-jti replay protection entries so they
// can coexist with other keys in a shared cache backend.
const jtiCacheKeyPrefix = "pkjwt:jti:"

// Errors returned by ClientAssertionVerifier. All are presented to the caller as
// OAuth invalid_client — the distinction is useful for audit logs and tests.
var (
	ErrAssertionFeatureDisabled = errors.New("private_key_jwt is disabled")
	ErrAssertionTypeInvalid     = errors.New("invalid client_assertion_type")
	ErrAssertionMalformed       = errors.New("malformed client_assertion")
	ErrAssertionIssuerMismatch  = errors.New("client_assertion iss/sub mismatch")
	ErrAssertionClientUnknown   = errors.New(
		"client_assertion issuer is not a registered client",
	)
	ErrAssertionClientInactive    = errors.New("client is not active")
	ErrAssertionMethodNotAllowed  = errors.New("client is not configured for private_key_jwt")
	ErrAssertionKeyLookup         = errors.New("unable to resolve client signing key")
	ErrAssertionSignatureInvalid  = errors.New("client_assertion signature is invalid")
	ErrAssertionAlgorithmMismatch = errors.New(
		"client_assertion algorithm does not match client registration",
	)
	ErrAssertionAudienceInvalid     = errors.New("client_assertion audience is invalid")
	ErrAssertionExpired             = errors.New("client_assertion is expired")
	ErrAssertionNotYetValid         = errors.New("client_assertion is not yet valid")
	ErrAssertionLifetimeTooLong     = errors.New("client_assertion lifetime exceeds server maximum")
	ErrAssertionMissingJTI          = errors.New("client_assertion is missing jti")
	ErrAssertionJTIReplay           = errors.New("client_assertion jti was already used")
	ErrAssertionJTICacheUnavailable = errors.New("client_assertion jti replay cache unavailable")
	ErrAssertionMissingRequiredTime = errors.New("client_assertion is missing required time claims")
)

// ClientAssertionConfig controls the verifier's behaviour. All durations are
// positive; the caller is responsible for providing sensible defaults.
type ClientAssertionConfig struct {
	Enabled           bool
	ExpectedAudiences []string // at least one must be present in the aud claim
	MaxLifetime       time.Duration
	ClockSkew         time.Duration
}

// ClientAssertionVerifier validates JWT Bearer Assertions presented as
// client_assertion at the token endpoint (RFC 7523).
type ClientAssertionVerifier struct {
	clientService *ClientService
	jwksFetcher   *JWKSFetcher
	jtiCache      core.Cache[bool]
	auditService  core.AuditLogger
	cfg           ClientAssertionConfig

	// jtiLocks shards the jti replay Get+Set critical section per client to
	// keep honest traffic free of cross-client contention while still closing
	// the TOCTOU window for concurrent requests carrying the same jti.
	jtiLocks sync.Map // map[string]*sync.Mutex, keyed by client_id
}

// NewClientAssertionVerifier wires the verifier. auditService may be nil (no-op).
// jtiCache must be supplied — it is required for RFC 7523 §3 replay prevention.
func NewClientAssertionVerifier(
	clientService *ClientService,
	jwksFetcher *JWKSFetcher,
	jtiCache core.Cache[bool],
	auditService core.AuditLogger,
	cfg ClientAssertionConfig,
) *ClientAssertionVerifier {
	if auditService == nil {
		auditService = NewNoopAuditService()
	}
	if cfg.MaxLifetime <= 0 {
		cfg.MaxLifetime = 5 * time.Minute
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	return &ClientAssertionVerifier{
		clientService: clientService,
		jwksFetcher:   jwksFetcher,
		jtiCache:      jtiCache,
		auditService:  auditService,
		cfg:           cfg,
	}
}

// Verify validates the provided JWT assertion and returns the authenticated
// OAuth client. All error returns are safe to surface as OAuth invalid_client.
func (v *ClientAssertionVerifier) Verify(
	ctx context.Context,
	assertion, assertionType string,
) (*models.OAuthApplication, error) {
	if !v.cfg.Enabled {
		return nil, ErrAssertionFeatureDisabled
	}
	if assertionType != AssertionType {
		return nil, ErrAssertionTypeInvalid
	}
	if strings.TrimSpace(assertion) == "" {
		return nil, ErrAssertionMalformed
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, _, err := parser.ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssertionMalformed, err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrAssertionMalformed
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" || iss != sub {
		v.logFailure(ctx, iss, ErrAssertionIssuerMismatch.Error())
		return nil, ErrAssertionIssuerMismatch
	}

	client, err := v.clientService.GetClient(ctx, iss)
	if err != nil {
		v.logFailure(ctx, iss, "client lookup failed")
		if errors.Is(err, ErrClientNotFound) {
			return nil, ErrAssertionClientUnknown
		}
		return nil, ErrAssertionClientUnknown
	}
	if !client.IsActive() {
		v.logFailure(ctx, iss, "client inactive")
		return nil, ErrAssertionClientInactive
	}
	if !client.UsesPrivateKeyJWT() {
		v.logFailure(ctx, iss, "client not configured for private_key_jwt")
		return nil, ErrAssertionMethodNotAllowed
	}

	// Algorithm must match the one registered with the client.
	if tok.Method.Alg() != client.TokenEndpointAuthSigningAlg {
		v.logFailure(ctx, iss, fmt.Sprintf(
			"algorithm mismatch: header=%s registered=%s",
			tok.Method.Alg(), client.TokenEndpointAuthSigningAlg,
		))
		return nil, ErrAssertionAlgorithmMismatch
	}

	kid, _ := tok.Header["kid"].(string)
	jwkSet, err := v.resolveJWKS(ctx, client, kid)
	if err != nil {
		v.logFailure(ctx, iss, err.Error())
		return nil, fmt.Errorf("%w: %v", ErrAssertionKeyLookup, err)
	}
	jwk := jwkSet.FindByKid(kid)
	if jwk == nil {
		v.logFailure(ctx, iss, fmt.Sprintf("no matching JWK for kid=%q", kid))
		return nil, fmt.Errorf("%w: no matching kid", ErrAssertionKeyLookup)
	}
	pubKey, err := jwk.ToPublicKey()
	if err != nil {
		v.logFailure(ctx, iss, fmt.Sprintf("public key decode failed: %v", err))
		return nil, fmt.Errorf("%w: %v", ErrAssertionKeyLookup, err)
	}

	// Verify signature with strict algorithm enforcement. Library-side claim
	// validation is disabled so our custom skew and lifetime caps apply below.
	verifyParser := jwt.NewParser(
		jwt.WithValidMethods([]string{client.TokenEndpointAuthSigningAlg}),
		jwt.WithoutClaimsValidation(),
	)
	if _, err := verifyParser.Parse(assertion, func(_ *jwt.Token) (any, error) {
		return pubKey, nil
	}); err != nil {
		v.logFailure(ctx, iss, fmt.Sprintf("signature verification failed: %v", err))
		return nil, ErrAssertionSignatureInvalid
	}

	if err := v.validateTimeClaims(claims); err != nil {
		v.logFailure(ctx, iss, err.Error())
		return nil, err
	}
	if err := v.validateAudience(claims); err != nil {
		v.logFailure(ctx, iss, err.Error())
		return nil, err
	}
	if err := v.checkJTIReplay(ctx, iss, claims); err != nil {
		v.logFailure(ctx, iss, err.Error())
		return nil, err
	}

	v.logSuccess(ctx, client)
	return client, nil
}

func (v *ClientAssertionVerifier) resolveJWKS(
	ctx context.Context,
	client *models.OAuthApplication,
	kid string,
) (*util.JWKSet, error) {
	if client.JWKS != "" {
		set, err := util.ParseJWKSet(client.JWKS)
		if err != nil {
			return nil, fmt.Errorf("parse inline JWKS: %w", err)
		}
		return set, nil
	}
	if client.JWKSURI == "" {
		return nil, errors.New("client has no JWKS configured")
	}
	if v.jwksFetcher == nil {
		return nil, errors.New("JWKS fetcher not configured")
	}
	return v.jwksFetcher.GetWithRefresh(ctx, client.JWKSURI, kid)
}

func (v *ClientAssertionVerifier) validateTimeClaims(claims jwt.MapClaims) error {
	now := time.Now()
	skew := v.cfg.ClockSkew

	expF, ok := claims["exp"].(float64)
	if !ok {
		return ErrAssertionMissingRequiredTime
	}
	iatF, ok := claims["iat"].(float64)
	if !ok {
		return ErrAssertionMissingRequiredTime
	}
	exp := time.Unix(int64(expF), 0)
	iat := time.Unix(int64(iatF), 0)

	if now.After(exp.Add(skew)) {
		return ErrAssertionExpired
	}
	if iat.Sub(now) > skew {
		return ErrAssertionNotYetValid
	}
	if nbfF, ok := claims["nbf"].(float64); ok {
		nbf := time.Unix(int64(nbfF), 0)
		if nbf.Sub(now) > skew {
			return ErrAssertionNotYetValid
		}
	}
	// exp must be strictly after iat: a zero or negative lifetime is
	// nonsensical and would otherwise pass the MaxLifetime bound below.
	if !exp.After(iat) {
		return ErrAssertionLifetimeTooLong
	}
	if exp.Sub(iat) > v.cfg.MaxLifetime {
		return ErrAssertionLifetimeTooLong
	}
	return nil
}

func (v *ClientAssertionVerifier) validateAudience(claims jwt.MapClaims) error {
	raw, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("%w: missing aud", ErrAssertionAudienceInvalid)
	}
	audValues := extractAudienceValues(raw)
	if len(audValues) == 0 {
		return fmt.Errorf("%w: empty aud", ErrAssertionAudienceInvalid)
	}
	for _, expected := range v.cfg.ExpectedAudiences {
		if expected == "" {
			continue
		}
		if slices.Contains(audValues, expected) {
			return nil
		}
	}
	return fmt.Errorf("%w: aud %v not accepted", ErrAssertionAudienceInvalid, audValues)
}

func extractAudienceValues(raw any) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

func (v *ClientAssertionVerifier) checkJTIReplay(
	ctx context.Context,
	clientID string,
	claims jwt.MapClaims,
) error {
	jti, _ := claims["jti"].(string)
	if strings.TrimSpace(jti) == "" {
		return ErrAssertionMissingJTI
	}
	if v.jtiCache == nil {
		// Without a cache we cannot prevent replay. Fail closed using the
		// dedicated sentinel so callers/tests can distinguish this from an
		// actual replay via errors.Is.
		return ErrAssertionJTICacheUnavailable
	}
	key := jtiCacheKeyPrefix + clientID + ":" + jti

	// Serialise the Get+Set pair per client so two concurrent requests
	// carrying the same jti cannot both observe a cache miss before either
	// Set lands. Sharding by client keeps honest high-throughput traffic
	// free of cross-client contention.
	lockIface, _ := v.jtiLocks.LoadOrStore(clientID, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	switch _, err := v.jtiCache.Get(ctx, key); {
	case err == nil:
		return ErrAssertionJTIReplay
	case errors.Is(err, cache.ErrCacheMiss):
		// expected — the jti has not been seen; fall through to record it.
	default:
		// Backend error (e.g. Redis unavailable). Fail closed so we do not
		// silently accept replays while the cache is degraded. Use a
		// distinct error so audit logs don't misreport a cache outage as
		// a replay attempt.
		log.Printf("[ClientAssertion] jti cache lookup failed: %v", err)
		return ErrAssertionJTICacheUnavailable
	}
	// TTL = remaining assertion lifetime + clock skew. If exp is absent,
	// fall back to MaxLifetime (defensive).
	ttl := v.cfg.MaxLifetime + v.cfg.ClockSkew
	if expF, ok := claims["exp"].(float64); ok {
		remaining := time.Until(time.Unix(int64(expF), 0)) + v.cfg.ClockSkew
		if remaining > 0 {
			ttl = remaining
		}
	}
	if err := v.jtiCache.Set(ctx, key, true, ttl); err != nil {
		// Set failure after a miss: reject the assertion rather than
		// silently skipping replay tracking. Use the dedicated cache-
		// unavailable error so audit logs are accurate.
		log.Printf("[ClientAssertion] failed to record jti %s: %v", jti, err)
		return ErrAssertionJTICacheUnavailable
	}
	return nil
}

func (v *ClientAssertionVerifier) logSuccess(
	ctx context.Context,
	client *models.OAuthApplication,
) {
	v.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventClientAssertionVerified,
		Severity:     models.SeverityInfo,
		ActorUserID:  "client:" + client.ClientID,
		ResourceType: models.ResourceClient,
		ResourceID:   client.ClientID,
		ResourceName: client.ClientName,
		Action:       "client_assertion verified",
		Details: models.AuditDetails{
			"signing_alg": client.TokenEndpointAuthSigningAlg,
		},
		Success: true,
	})
}

func (v *ClientAssertionVerifier) logFailure(
	ctx context.Context,
	issuer, reason string,
) {
	v.auditService.Log(ctx, core.AuditLogEntry{
		EventType:    models.EventClientAssertionFailed,
		Severity:     models.SeverityWarning,
		ActorUserID:  "client:" + issuer,
		ResourceType: models.ResourceClient,
		ResourceID:   issuer,
		Action:       "client_assertion rejected",
		Details: models.AuditDetails{
			"reason": reason,
		},
		Success: false,
	})
}
