package bootstrap

import (
	"context"
	"embed"
	"net/http"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/appleboy/graceful"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// Application holds all initialized components
type Application struct {
	Config *config.Config

	// Graceful shutdown manager
	manager *graceful.Manager

	// Core infrastructure
	DB                   *store.Store
	MetricsRecorder      metrics.Recorder
	MetricsCache         cache.Cache[int64]
	MetricsCacheCloser   func() error
	UserCache            cache.Cache[models.User]
	UserCacheCloser      func() error
	RateLimitRedisClient *redis.Client

	// Services
	AuditService         *services.AuditService
	UserService          *services.UserService
	DeviceService        *services.DeviceService
	TokenService         *services.TokenService
	ClientService        *services.ClientService
	AuthorizationService *services.AuthorizationService

	// HTTP
	HandlerSet  handlerSet
	Router      *gin.Engine
	Server      *http.Server
	TemplatesFS embed.FS
}

// Run initializes and starts the application
func Run(cfg *config.Config, templatesFS embed.FS) error {
	// Create root context for the entire application lifecycle
	ctx := context.Background()

	// Create graceful manager with root context
	m := graceful.NewManagerWithContext(ctx)

	app := &Application{
		Config:      cfg,
		TemplatesFS: templatesFS,
		manager:     m, // Store manager for later use
	}

	// Phase 1: Validate configuration
	validateAllConfiguration(cfg)

	// Phase 2: Initialize infrastructure (with shutdown context for cancellation)
	if err := app.initializeInfrastructure(m.ShutdownContext()); err != nil {
		return err
	}

	// Phase 3: Initialize business layer (no I/O, no context needed)
	app.initializeBusinessLayer()

	// Phase 4: Initialize HTTP layer (no I/O, no context needed)
	app.initializeHTTPLayer()

	// Phase 5: Start server with graceful shutdown
	app.startWithGracefulShutdown()

	return nil
}

// initializeInfrastructure sets up database, metrics, cache, and Redis
func (app *Application) initializeInfrastructure(ctx context.Context) error {
	var err error

	// Database
	app.DB, err = initializeDatabase(ctx, app.Config)
	if err != nil {
		return err
	}

	// Metrics
	app.MetricsRecorder = initializeMetrics(app.Config)

	// Metrics Cache
	app.MetricsCache, app.MetricsCacheCloser, err = initializeMetricsCache(ctx, app.Config)
	if err != nil {
		return err
	}

	// User Cache
	app.UserCache, app.UserCacheCloser, err = initializeUserCache(ctx, app.Config)
	if err != nil {
		return err
	}

	// Redis (for rate limiting)
	app.RateLimitRedisClient, err = initializeRateLimitRedisClient(ctx, app.Config)
	if err != nil {
		return err
	}

	return nil
}

// initializeBusinessLayer sets up services
func (app *Application) initializeBusinessLayer() {
	// Audit service (required by other services)
	app.AuditService = services.NewAuditService(
		app.DB,
		app.Config.EnableAuditLogging,
		app.Config.AuditLogBufferSize,
	)

	// Initialize all business services
	app.UserService,
		app.DeviceService,
		app.TokenService,
		app.ClientService,
		app.AuthorizationService = initializeServices(
		app.Config,
		app.DB,
		app.AuditService,
		app.MetricsRecorder,
		app.UserCache,
	)
}

// initializeHTTPLayer sets up handlers, router, and server
func (app *Application) initializeHTTPLayer() {
	// OAuth setup
	oauthProviders := initializeOAuthProviders(app.Config)
	logOAuthProvidersStatus(oauthProviders)
	oauthHTTPClient := createOAuthHTTPClient(app.Config)

	// Handlers
	app.HandlerSet = initializeHandlers(
		app.Config,
		app.UserService,
		app.DeviceService,
		app.TokenService,
		app.ClientService,
		app.AuthorizationService,
		app.AuditService,
		oauthProviders,
		oauthHTTPClient,
		app.MetricsRecorder,
	)

	// Router
	app.Router = setupRouter(
		app.Config,
		app.DB,
		app.HandlerSet,
		app.MetricsRecorder,
		app.AuditService,
		app.RateLimitRedisClient,
		app.TemplatesFS,
	)

	// HTTP Server
	app.Server = createHTTPServer(app.Config, app.Router)
}

// startWithGracefulShutdown starts the server and handles graceful shutdown
func (app *Application) startWithGracefulShutdown() {
	m := app.manager // Use stored manager instance

	// Add jobs
	addServerRunningJob(m, app.Server)
	addServerShutdownJob(m, app.Server, app.Config)
	addAuditServiceShutdownJob(m, app.AuditService, app.Config)
	addRedisClientShutdownJob(m, app.RateLimitRedisClient, app.Config)
	addCacheCleanupJob(m, app.MetricsCache, app.Config)
	addUserCacheCleanupJob(m, app.UserCache, app.Config)
	addDatabaseShutdownJob(m, app.DB, app.Config)
	addAuditLogCleanupJob(m, app.Config, app.AuditService)
	addMetricsGaugeUpdateJob(m, app.Config, app.DB, app.MetricsRecorder, app.MetricsCache)

	// Wait for graceful shutdown
	<-m.Done()
}
