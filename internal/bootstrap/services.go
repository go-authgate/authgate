package bootstrap

import (
	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
)

// initializeServices creates all business logic services
func initializeServices(
	cfg *config.Config,
	db *store.Store,
	auditService *services.AuditService,
	prometheusMetrics core.Recorder,
	userCache core.Cache[models.User],
) (*services.UserService, *services.DeviceService, *services.TokenService, *services.ClientService, *services.AuthorizationService) {
	// Initialize authentication providers
	localProvider := auth.NewLocalAuthProvider(db)
	httpAPIProvider := initializeHTTPAPIAuthProvider(cfg)

	// Initialize token provider (single interface, mode selected at bootstrap time)
	tokenProvider := initializeTokenProvider(cfg)

	// Initialize services
	userService := services.NewUserService(
		db,
		localProvider,
		httpAPIProvider,
		cfg.AuthMode,
		cfg.OAuthAutoRegister,
		auditService,
		userCache,
		cfg.UserCacheTTL,
	)
	deviceService := services.NewDeviceService(db, cfg, auditService, prometheusMetrics)
	tokenService := services.NewTokenService(
		db,
		cfg,
		deviceService,
		tokenProvider,
		auditService,
		prometheusMetrics,
	)
	clientService := services.NewClientService(db, auditService)
	authorizationService := services.NewAuthorizationService(db, cfg, auditService)

	return userService, deviceService, tokenService, clientService, authorizationService
}
