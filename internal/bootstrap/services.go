package bootstrap

import (
	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/token"
)

// initializeServices creates all business logic services
func initializeServices(
	cfg *config.Config,
	db *store.Store,
	auditService *services.AuditService,
	prometheusMetrics metrics.Recorder,
) (*services.UserService, *services.DeviceService, *services.TokenService, *services.ClientService, *services.AuthorizationService) {
	// Initialize authentication providers
	localProvider := auth.NewLocalAuthProvider(db)
	httpAPIProvider := initializeHTTPAPIAuthProvider(cfg)

	// Initialize token providers
	localTokenProvider := token.NewLocalTokenProvider(cfg)
	httpTokenProvider := initializeHTTPTokenProvider(cfg)

	// Initialize services
	userService := services.NewUserService(
		db,
		localProvider,
		httpAPIProvider,
		cfg.AuthMode,
		cfg.OAuthAutoRegister,
		auditService,
	)
	deviceService := services.NewDeviceService(db, cfg, auditService, prometheusMetrics)
	tokenService := services.NewTokenService(
		db,
		cfg,
		deviceService,
		localTokenProvider,
		httpTokenProvider,
		cfg.TokenProviderMode,
		auditService,
		prometheusMetrics,
	)
	clientService := services.NewClientService(db, auditService)
	authorizationService := services.NewAuthorizationService(db, cfg, auditService)

	return userService, deviceService, tokenService, clientService, authorizationService
}
