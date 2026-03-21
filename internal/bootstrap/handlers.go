package bootstrap

import (
	"crypto"
	"embed"
	"net/http"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/handlers"
	"github.com/go-authgate/authgate/internal/services"
)

// handlerSet holds all HTTP handlers and required services
type handlerSet struct {
	auth          *handlers.AuthHandler
	device        *handlers.DeviceHandler
	token         *handlers.TokenHandler
	client        *handlers.ClientHandler
	userClient    *handlers.UserClientHandler
	session       *handlers.SessionHandler
	oauth         *handlers.OAuthHandler
	audit         *handlers.AuditHandler
	authorization *handlers.AuthorizationHandler
	oidc          *handlers.OIDCHandler
	registration  *handlers.RegistrationHandler
	docs          *handlers.DocsHandler
	jwks          *handlers.JWKSHandler
	userService   *services.UserService
}

// handlerDeps holds all dependencies needed to construct the handler set
type handlerDeps struct {
	cfg            *config.Config
	services       serviceSet
	auditService   *services.AuditService
	oauthProviders map[string]*auth.OAuthProvider
	oauthClient    *http.Client
	metrics        core.Recorder
	templatesFS    embed.FS
	tokenProvider  core.TokenProvider
}

// initializeHandlers creates all HTTP handlers
func initializeHandlers(deps handlerDeps) handlerSet {
	// Build JWKS handler from the token provider's public key info
	jwksHandler := buildJWKSHandler(deps.tokenProvider, deps.cfg)

	return handlerSet{
		auth: handlers.NewAuthHandler(
			deps.services.user,
			deps.cfg,
			deps.metrics,
		),
		device: handlers.NewDeviceHandler(
			deps.services.device,
			deps.services.user,
			deps.services.authorization,
			deps.cfg,
		),
		token: handlers.NewTokenHandler(
			deps.services.token,
			deps.services.authorization,
			deps.cfg,
		),
		client:     handlers.NewClientHandler(deps.services.client, deps.services.authorization),
		userClient: handlers.NewUserClientHandler(deps.services.client),
		session:    handlers.NewSessionHandler(deps.services.token),
		oauth: handlers.NewOAuthHandler(
			deps.oauthProviders,
			deps.services.user,
			deps.oauthClient,
			deps.cfg.BaseURL,
			deps.cfg.SessionFingerprint,
			deps.cfg.SessionFingerprintIP,
			deps.metrics,
		),
		audit: handlers.NewAuditHandler(deps.auditService),
		authorization: handlers.NewAuthorizationHandler(
			deps.services.authorization,
			deps.services.token,
			deps.services.user,
			deps.cfg,
		),
		oidc: handlers.NewOIDCHandler(
			deps.services.token, deps.services.user,
			deps.cfg, len(jwksHandler.Keys()) > 0,
			isIDTokenSupported(deps.tokenProvider),
		),
		registration: handlers.NewRegistrationHandler(
			deps.services.client,
			deps.auditService,
			deps.cfg,
		),
		docs:        handlers.NewDocsHandler(deps.templatesFS),
		jwks:        jwksHandler,
		userService: deps.services.user,
	}
}

// jwksInfoProvider is implemented by LocalTokenProvider to expose public key metadata.
type jwksInfoProvider interface {
	PublicKey() crypto.PublicKey
	KeyID() string
	Algorithm() string
}

// isIDTokenSupported returns true when the token provider can generate OIDC ID tokens.
func isIDTokenSupported(tp core.TokenProvider) bool {
	_, ok := tp.(core.IDTokenProvider)
	return ok
}

// buildJWKSHandler creates a JWKS handler from the token provider.
// For LocalTokenProvider with asymmetric keys, it exposes the public key.
// For HS256, it returns an empty key set.
func buildJWKSHandler(tp core.TokenProvider, cfg *config.Config) *handlers.JWKSHandler {
	if info, ok := tp.(jwksInfoProvider); ok {
		return handlers.NewJWKSHandler(info.Algorithm(), info.KeyID(), info.PublicKey())
	}
	// Fallback: empty JWKS
	return handlers.NewJWKSHandler(cfg.JWTSigningAlgorithm, "", nil)
}
