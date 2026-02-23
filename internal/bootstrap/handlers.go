package bootstrap

import (
	"net/http"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/handlers"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/services"
)

// handlerSet holds all HTTP handlers and required services
type handlerSet struct {
	auth          *handlers.AuthHandler
	device        *handlers.DeviceHandler
	token         *handlers.TokenHandler
	client        *handlers.ClientHandler
	session       *handlers.SessionHandler
	oauth         *handlers.OAuthHandler
	audit         *handlers.AuditHandler
	authorization *handlers.AuthorizationHandler
	oidc          *handlers.OIDCHandler
	userService   *services.UserService
}

// initializeHandlers creates all HTTP handlers
func initializeHandlers(
	cfg *config.Config,
	userService *services.UserService,
	deviceService *services.DeviceService,
	tokenService *services.TokenService,
	clientService *services.ClientService,
	authorizationService *services.AuthorizationService,
	auditService *services.AuditService,
	oauthProviders map[string]*auth.OAuthProvider,
	oauthHTTPClient *http.Client,
	prometheusMetrics metrics.Recorder,
) handlerSet {
	return handlerSet{
		auth: handlers.NewAuthHandler(
			userService,
			cfg.BaseURL,
			cfg.SessionFingerprint,
			cfg.SessionFingerprintIP,
			prometheusMetrics,
		),
		device:  handlers.NewDeviceHandler(deviceService, userService, authorizationService, cfg),
		token:   handlers.NewTokenHandler(tokenService, authorizationService, cfg),
		client:  handlers.NewClientHandler(clientService, authorizationService),
		session: handlers.NewSessionHandler(tokenService, userService),
		oauth: handlers.NewOAuthHandler(
			oauthProviders,
			userService,
			oauthHTTPClient,
			cfg.SessionFingerprint,
			cfg.SessionFingerprintIP,
			prometheusMetrics,
		),
		audit: handlers.NewAuditHandler(auditService),
		authorization: handlers.NewAuthorizationHandler(
			authorizationService,
			tokenService,
			userService,
			cfg,
		),
		oidc:        handlers.NewOIDCHandler(tokenService, userService, cfg),
		userService: userService,
	}
}
