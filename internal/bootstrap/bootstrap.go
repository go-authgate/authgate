package bootstrap

import (
	"embed"
	"net/http"

	"github.com/appleboy/authgate/internal/cache"
	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/metrics"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/store"

	"github.com/appleboy/graceful"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// Application holds all initialized components
type Application struct {
	Config *config.Config

	// Core infrastructure
	DB                   *store.Store
	MetricsRecorder      metrics.MetricsRecorder
	MetricsCache         cache.Cache
	MetricsCacheCloser   func() error
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
	app := &Application{
		Config:      cfg,
		TemplatesFS: templatesFS,
	}

	// Phase 1: Validate configuration
	validateAllConfiguration(cfg)

	// Phase 2: Initialize infrastructure
	if err := app.initializeInfrastructure(); err != nil {
		return err
	}

	// Phase 3: Initialize business layer
	app.initializeBusinessLayer()

	// Phase 4: Initialize HTTP layer
	app.initializeHTTPLayer()

	// Phase 5: Start server with graceful shutdown
	app.startWithGracefulShutdown()

	return nil
}

// initializeInfrastructure sets up database, metrics, cache, and Redis
func (app *Application) initializeInfrastructure() error {
	var err error

	// Database
	app.DB, err = initializeDatabase(app.Config)
	if err != nil {
		return err
	}

	// Metrics
	app.MetricsRecorder = initializeMetrics(app.Config)
	app.MetricsCache, app.MetricsCacheCloser = initializeMetricsCache(app.Config)

	// Redis (for rate limiting)
	app.RateLimitRedisClient, err = initializeRateLimitRedisClient(app.Config)
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
	m := graceful.NewManager()

	// Add jobs
	addServerRunningJob(m, app.Server)
	addServerShutdownJob(m, app.Server)
	addRedisClientShutdownJob(m, app.RateLimitRedisClient)
	addAuditServiceShutdownJob(m, app.AuditService)
	addAuditLogCleanupJob(m, app.Config, app.AuditService)
	addMetricsGaugeUpdateJob(m, app.Config, app.DB, app.MetricsRecorder, app.MetricsCache)
	addCacheCleanupJob(m, app.MetricsCacheCloser)

	// Wait for graceful shutdown
	<-m.Done()
}
