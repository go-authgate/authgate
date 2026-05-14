package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var _ core.TokenProvider = (*LocalTokenProvider)(nil)

// LocalTokenProvider generates and validates JWT tokens locally
type LocalTokenProvider struct {
	config    *config.Config
	method    jwt.SigningMethod // HS256 / RS256 / ES256
	signKey   any               // []byte (HS256) / *rsa.PrivateKey / *ecdsa.PrivateKey
	verifyKey any               // []byte (HS256) / *rsa.PublicKey / *ecdsa.PublicKey
	keyID     string            // "kid" header value (empty for HS256)
	// stripList is the per-deployment list of claim keys generateJWT must
	// strip from caller-supplied extraClaims before signing. Computed once
	// at construction time from the configured private-claim prefix — see
	// computeStripList for the contents and rationale.
	stripList []string
}

// Option configures a LocalTokenProvider.
type Option func(*LocalTokenProvider)

// WithSigningKey sets the asymmetric signing and verification keys.
// Only *rsa.PrivateKey/*rsa.PublicKey (RS256) and *ecdsa.PrivateKey/*ecdsa.PublicKey (ES256)
// are supported; NewLocalTokenProvider validates concrete types and returns an error on mismatch.
func WithSigningKey(privateKey crypto.Signer, publicKey crypto.PublicKey) Option {
	return func(p *LocalTokenProvider) {
		p.signKey = privateKey
		p.verifyKey = publicKey
	}
}

// WithKeyID sets the "kid" JWT header value.
func WithKeyID(kid string) Option {
	return func(p *LocalTokenProvider) {
		p.keyID = kid
	}
}

// NewLocalTokenProvider creates a new local token provider.
// By default it uses HS256. Use WithSigningKey and WithKeyID for asymmetric algorithms.
// Returns an error if the algorithm requires an asymmetric key but none was provided.
func NewLocalTokenProvider(cfg *config.Config, opts ...Option) (*LocalTokenProvider, error) {
	p := &LocalTokenProvider{config: cfg}

	// Apply options first so signKey can be set before choosing method
	for _, opt := range opts {
		opt(p)
	}

	// Determine signing method from config
	switch cfg.JWTSigningAlgorithm {
	case config.AlgRS256:
		p.method = jwt.SigningMethodRS256
		if p.signKey == nil || p.verifyKey == nil {
			return nil, errors.New(
				"NewLocalTokenProvider: RS256 requires a signing key; use WithSigningKey",
			)
		}
		privKey, ok := p.signKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf(
				"NewLocalTokenProvider: RS256 requires *rsa.PrivateKey, got %T",
				p.signKey,
			)
		}
		pubKey, ok := p.verifyKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(
				"NewLocalTokenProvider: RS256 requires *rsa.PublicKey, got %T",
				p.verifyKey,
			)
		}
		if privKey.N.BitLen() < 2048 {
			return nil, fmt.Errorf(
				"NewLocalTokenProvider: RS256 requires at least 2048-bit RSA key, got %d-bit",
				privKey.N.BitLen(),
			)
		}
		derivedPub := &privKey.PublicKey
		if pubKey.E != derivedPub.E || pubKey.N.Cmp(derivedPub.N) != 0 {
			return nil, errors.New(
				"NewLocalTokenProvider: RS256 signing and verification keys do not match",
			)
		}
	case config.AlgES256:
		p.method = jwt.SigningMethodES256
		if p.signKey == nil || p.verifyKey == nil {
			return nil, errors.New(
				"NewLocalTokenProvider: ES256 requires a signing key; use WithSigningKey",
			)
		}
		ecKey, ok := p.signKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf(
				"NewLocalTokenProvider: ES256 requires *ecdsa.PrivateKey, got %T",
				p.signKey,
			)
		}
		if ecKey.Curve != elliptic.P256() {
			return nil, fmt.Errorf(
				"NewLocalTokenProvider: ES256 requires P-256 curve, got %s",
				ecKey.Curve.Params().Name,
			)
		}
		pubKey, ok := p.verifyKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(
				"NewLocalTokenProvider: ES256 requires *ecdsa.PublicKey, got %T",
				p.verifyKey,
			)
		}
		if pubKey.Curve != elliptic.P256() {
			return nil, fmt.Errorf(
				"NewLocalTokenProvider: ES256 requires P-256 curve for public key, got %s",
				pubKey.Curve.Params().Name,
			)
		}
		if ecKey.X.Cmp(pubKey.X) != 0 || ecKey.Y.Cmp(pubKey.Y) != 0 {
			return nil, errors.New(
				"NewLocalTokenProvider: ES256 signing and verification keys do not match",
			)
		}
	case config.AlgHS256, "":
		// HS256 (default)
		p.method = jwt.SigningMethodHS256
		p.signKey = []byte(cfg.JWTSecret)
		p.verifyKey = []byte(cfg.JWTSecret)
		p.keyID = ""
	default:
		return nil, fmt.Errorf(
			"NewLocalTokenProvider: unsupported JWTSigningAlgorithm %q",
			cfg.JWTSigningAlgorithm,
		)
	}

	// Mirror Load()'s default so ad-hoc test configs that build Config{}
	// directly (without going through Load) get production-equivalent
	// strip semantics. Without this fallback, an empty prefix would
	// trigger the cross-prefix strip and delete legitimate "extra_*"
	// extra-claims callers passed verbatim.
	prefix := cfg.JWTPrivateClaimPrefix
	if prefix == "" {
		prefix = config.DefaultJWTPrivateClaimPrefix
	}
	p.stripList = computeStripList(prefix)

	return p, nil
}

// PublicKey returns the asymmetric public verification key.
// Returns nil for HS256 (symmetric key).
func (p *LocalTokenProvider) PublicKey() crypto.PublicKey {
	switch p.verifyKey.(type) {
	case []byte:
		return nil // HS256 symmetric secret
	default:
		return p.verifyKey
	}
}

// KeyID returns the "kid" value used in JWT headers.
func (p *LocalTokenProvider) KeyID() string {
	return p.keyID
}

// Algorithm returns the JWT signing algorithm name (e.g. "HS256", "RS256", "ES256").
func (p *LocalTokenProvider) Algorithm() string {
	return p.method.Alg()
}

// signClaims creates a signed JWT from the given claims using the provider's
// signing method, key, and optional kid header. Shared by generateJWT and GenerateIDToken.
func (p *LocalTokenProvider) signClaims(claims jwt.MapClaims) (string, error) {
	tok := jwt.NewWithClaims(p.method, claims)
	if p.keyID != "" {
		tok.Header["kid"] = p.keyID
	}
	signed, err := tok.SignedString(p.signKey)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTokenGeneration, err)
	}
	return signed, nil
}

// generateJWT creates a signed JWT token with the given claims and expiration.
//
// extraClaims (optional) is merged into the JWT first, then standard claims are
// applied on top — standard claims always win, so callers cannot override
// iss/sub/exp/iat/jti/aud/type/scope/user_id/client_id by accident.
//
// When audienceOverride is non-empty, it replaces p.config.JWTAudience for
// this issuance (RFC 8707 Resource Indicators). A single value is emitted as
// a string, multiple values as an array, and an empty list (or empty
// JWTAudience) omits the claim entirely (RFC 7519 §4.1.3). Caller-supplied
// "aud" inside extraClaims is always stripped.
func (p *LocalTokenProvider) generateJWT(
	userID, clientID, scopes, tokenType string,
	expiresAt time.Time,
	extraClaims map[string]any,
	audienceOverride []string,
) (*Result, error) {
	claims := jwt.MapClaims{}
	maps.Copy(claims, extraClaims)
	// Drop claims AuthGate intentionally strips from access/refresh tokens
	// because generateJWT does not set or preserve them for those token
	// types: the registered JWT claim nbf (RFC 7519), the OIDC ID-token
	// claims azp/amr/acr/auth_time/nonce/at_hash, and the bare logical
	// names of the AuthGate-emitted private-claim registry. A caller that
	// smuggles any of them past the parser would otherwise leak them into
	// the signed token — bare logical names in particular would let a
	// caller re-introduce the legacy `domain` / `project` / `service_account`
	// keys an un-migrated downstream might still trust during the
	// rolling-upgrade window. The server layer's prefixed private claims
	// (e.g. extra_domain) survive because computeStripList intentionally
	// excludes the configured <prefix>_<logical> keys from the strip set.
	for _, k := range p.stripList {
		delete(claims, k)
	}
	claims["user_id"] = userID
	claims["client_id"] = clientID
	claims["scope"] = scopes
	claims["type"] = tokenType
	claims["exp"] = expiresAt.Unix()
	claims["iat"] = time.Now().Unix()
	claims["iss"] = p.config.BaseURL
	claims["sub"] = userID
	claims["jti"] = uuid.New().String()
	// "aud" is governed entirely by the audience override (when present) or
	// the static config (when absent). Drop any value an extraClaims caller
	// may have copied in, then set it from the override or config. A caller
	// who wants to bind audience to a specific resource (RFC 8707) must pass
	// audienceOverride explicitly — smuggling via extraClaims is rejected.
	delete(claims, "aud")
	audSource := p.config.JWTAudience
	if len(audienceOverride) > 0 {
		audSource = audienceOverride
	}
	if aud := audienceClaim(audSource); aud != nil {
		claims["aud"] = aud
	}

	tokenString, err := p.signClaims(claims)
	if err != nil {
		return nil, err
	}

	return &Result{
		TokenString: tokenString,
		TokenType:   TokenTypeBearer,
		ExpiresAt:   expiresAt,
		Claims:      claims,
	}, nil
}

// audienceClaim returns the value to assign to the JWT "aud" claim, given the
// configured audience list. A single entry collapses to a plain string (the
// common case and most compatible with naive JWT consumers), multiple entries
// stay as a slice, and an empty list returns nil so the caller can skip the
// claim entirely.
func audienceClaim(aud []string) any {
	switch len(aud) {
	case 0:
		return nil
	case 1:
		return aud[0]
	default:
		out := make([]string, len(aud))
		copy(out, aud)
		return out
	}
}

// ParseJWT parses a JWT token, verifies its signature, and extracts standard claims.
// It does not check the "type" claim — callers (ValidateToken, ValidateRefreshToken)
// add their own type-specific checks on top.
func (p *LocalTokenProvider) ParseJWT(tokenString string) (*ValidationResult, error) {
	tok, err := jwt.Parse(tokenString, p.keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !tok.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	userID, _ := claims["user_id"].(string)
	clientID, _ := claims["client_id"].(string)
	scopes, _ := claims["scope"].(string)

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("%w: missing exp claim", ErrInvalidToken)
	}

	return &ValidationResult{
		Valid:     true,
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: time.Unix(int64(exp), 0),
		Claims:    claims,
	}, nil
}

// mapRefreshError translates base token errors to refresh-specific sentinel errors.
func mapRefreshError(err error) error {
	switch {
	case errors.Is(err, ErrExpiredToken):
		return ErrExpiredRefreshToken
	case errors.Is(err, ErrInvalidToken):
		return ErrInvalidRefreshToken
	default:
		return err
	}
}

// keyFunc validates the signing method and returns the verification key.
func (p *LocalTokenProvider) keyFunc(token *jwt.Token) (any, error) {
	if token.Method.Alg() != p.method.Alg() {
		return nil, fmt.Errorf(
			"unexpected signing method: got %q, expected %q",
			token.Method.Alg(), p.method.Alg(),
		)
	}
	return p.verifyKey, nil
}

// GenerateToken creates a JWT access token using local signing.
// If ttl > 0 it overrides p.config.JWTExpiration and no jitter is applied
// (the caller has chosen an explicit lifetime per client profile).
// When audience is non-empty, it overrides the static JWTAudience config
// for this token (RFC 8707 Resource Indicators).
func (p *LocalTokenProvider) GenerateToken(
	ctx context.Context,
	userID, clientID, scopes string,
	ttl time.Duration,
	extraClaims map[string]any,
	audience []string,
) (*Result, error) {
	var expiry time.Duration
	if ttl > 0 {
		expiry = ttl
	} else {
		expiry = p.config.JWTExpiration
		if p.config.JWTExpirationJitter > 0 {
			expiry += time.Duration(rand.Int64N(int64(p.config.JWTExpirationJitter)))
		}
	}
	expiresAt := time.Now().Add(expiry)
	return p.generateJWT(
		userID, clientID, scopes, TokenCategoryAccess, expiresAt, extraClaims, audience,
	)
}

// ValidateToken verifies a JWT access token using local verification.
// It rejects refresh tokens (type=="refresh") at the JWT level.
func (p *LocalTokenProvider) ValidateToken(
	ctx context.Context,
	tokenString string,
) (*ValidationResult, error) {
	result, err := p.ParseJWT(tokenString)
	if err != nil {
		return nil, err
	}

	tokenType, _ := result.Claims["type"].(string)
	if tokenType != TokenCategoryAccess {
		return nil, fmt.Errorf("%w: expected access token, got %q", ErrInvalidToken, tokenType)
	}

	return result, nil
}

// Name returns provider name for logging
func (p *LocalTokenProvider) Name() string {
	return "local"
}

// GenerateClientCredentialsToken creates an access token for the client_credentials grant.
// If ttl > 0 it overrides the default CLIENT_CREDENTIALS_TOKEN_EXPIRATION.
// The userID field carries the synthetic machine identity "client:<clientID>".
// When audience is non-empty, it overrides the static JWTAudience config.
func (p *LocalTokenProvider) GenerateClientCredentialsToken(
	ctx context.Context,
	userID, clientID, scopes string,
	ttl time.Duration,
	extraClaims map[string]any,
	audience []string,
) (*Result, error) {
	expiry := ttl
	if expiry <= 0 {
		expiry = p.config.ClientCredentialsTokenExpiration
	}
	expiresAt := time.Now().Add(expiry)
	return p.generateJWT(
		userID, clientID, scopes, TokenCategoryAccess, expiresAt, extraClaims, audience,
	)
}

// GenerateRefreshToken creates a refresh token JWT. If ttl > 0 it overrides
// the default REFRESH_TOKEN_EXPIRATION. When audience is non-empty, it
// overrides the static JWTAudience config.
func (p *LocalTokenProvider) GenerateRefreshToken(
	ctx context.Context,
	userID, clientID, scopes string,
	ttl time.Duration,
	extraClaims map[string]any,
	audience []string,
) (*Result, error) {
	expiry := ttl
	if expiry <= 0 {
		expiry = p.config.RefreshTokenExpiration
	}
	expiresAt := time.Now().Add(expiry)
	return p.generateJWT(
		userID, clientID, scopes, TokenCategoryRefresh, expiresAt, extraClaims, audience,
	)
}

// ValidateRefreshToken verifies a refresh token JWT
func (p *LocalTokenProvider) ValidateRefreshToken(
	ctx context.Context,
	tokenString string,
) (*ValidationResult, error) {
	result, err := p.ParseJWT(tokenString)
	if err != nil {
		return nil, mapRefreshError(err)
	}

	tokenType, _ := result.Claims["type"].(string)
	if tokenType != TokenCategoryRefresh {
		return nil, fmt.Errorf(
			"%w: expected refresh token, got %q",
			ErrInvalidRefreshToken,
			tokenType,
		)
	}

	return result, nil
}

// RefreshAccessToken generates new access token (and optionally new refresh token in rotation mode).
// accessTTL and refreshTTL override the default expirations when > 0, allowing
// the caller (TokenService) to apply the client's current TokenProfile at
// refresh time rather than reusing the TTL the original tokens were issued with.
//
// extraClaims is also re-applied here, so callers (TokenService) can inject the
// client's CURRENT project / service_account at refresh time rather than
// freezing values from the original issuance.
//
// accessAudience binds the access token's `aud` claim (RFC 8707). The caller
// (TokenService) is responsible for enforcing the §2.2 subset rule against
// the original grant before invoking this method. refreshAudience is kept
// separate so refresh tokens don't accidentally carry a resource-server
// audience — pass nil to use the static JWTAudience config.
func (p *LocalTokenProvider) RefreshAccessToken(
	ctx context.Context,
	refreshToken string,
	accessTTL, refreshTTL time.Duration,
	extraClaims map[string]any,
	accessAudience []string,
	refreshAudience []string,
) (*RefreshResult, error) {
	enableRotation := p.config.EnableTokenRotation
	// Validate the refresh token
	validationResult, err := p.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Generate new access token
	accessResult, err := p.GenerateToken(
		ctx,
		validationResult.UserID,
		validationResult.ClientID,
		validationResult.Scopes,
		accessTTL,
		extraClaims,
		accessAudience,
	)
	if err != nil {
		return nil, err
	}

	// Note: "type" claim already added in GenerateToken method

	result := &RefreshResult{
		AccessToken: accessResult,
	}

	// Generate new refresh token only in rotation mode
	if enableRotation {
		newRefreshToken, err := p.GenerateRefreshToken(
			ctx,
			validationResult.UserID,
			validationResult.ClientID,
			validationResult.Scopes,
			refreshTTL,
			extraClaims,
			refreshAudience,
		)
		if err != nil {
			return nil, err
		}
		result.RefreshToken = newRefreshToken
	}

	return result, nil
}
