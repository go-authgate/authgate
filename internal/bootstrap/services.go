package bootstrap

import (
	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
)

// serviceSet holds all initialized business logic services
type serviceSet struct {
	user          *services.UserService
	device        *services.DeviceService
	token         *services.TokenService
	client        *services.ClientService
	authorization *services.AuthorizationService
	dashboard     *services.DashboardService
}

// initializeServices creates all business logic services
func initializeServices(
	cfg *config.Config,
	db *store.Store,
	auditService core.AuditLogger,
	prometheusMetrics core.Recorder,
	userCache core.Cache[models.User],
	clientCountCache core.Cache[int64],
	clientCache core.Cache[models.OAuthApplication],
	tokenProvider core.TokenProvider,
	tokenCache core.Cache[models.AccessToken],
) serviceSet {
	// Initialize authentication providers
	localProvider := auth.NewLocalAuthProvider(db)
	httpAPIProvider := initializeHTTPAPIAuthProvider(cfg)

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
	clientService := services.NewClientService(
		db, auditService,
		clientCountCache, cfg.ClientCountCacheTTL,
		clientCache, cfg.ClientCacheTTL,
	)
	deviceService := services.NewDeviceService(
		db,
		cfg,
		auditService,
		prometheusMetrics,
		clientService,
	)
	tokenService := services.NewTokenService(
		db,
		cfg,
		deviceService,
		tokenProvider,
		auditService,
		prometheusMetrics,
		tokenCache,
		clientService,
	)
	authorizationService := services.NewAuthorizationService(
		db,
		cfg,
		auditService,
		tokenService,
		clientService,
	)
	dashboardService := services.NewDashboardService(db, auditService)

	return serviceSet{
		user:          userService,
		device:        deviceService,
		token:         tokenService,
		client:        clientService,
		authorization: authorizationService,
		dashboard:     dashboardService,
	}
}
