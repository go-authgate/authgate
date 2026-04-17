package bootstrap

import (
	"context"
	"embed"
	"net/http"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/appleboy/graceful"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/redis/rueidis/rueidislock"
)

// Application holds all initialized components
type Application struct {
	Config *config.Config

	// Graceful shutdown manager
	manager *graceful.Manager

	// Core infrastructure
	TokenProvider          core.TokenProvider
	DB                     *store.Store
	MetricsRecorder        core.Recorder
	MetricsCache           core.Cache[int64]
	MetricsCacheCloser     func() error
	UserCache              core.Cache[models.User]
	UserCacheCloser        func() error
	ClientCountCache       core.Cache[int64]
	ClientCountCacheCloser func() error
	ClientCache            core.Cache[models.OAuthApplication]
	ClientCacheCloser      func() error
	TokenCache             core.Cache[models.AccessToken]
	TokenCacheCloser       func() error
	RateLimitRedisClient   *redis.Client
	CleanupLocker          rueidislock.Locker

	// Services
	AuditService core.AuditLogger
	services     serviceSet

	// HTTP
	handlerSet  handlerSet
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

	// Client Count Cache (pending badge in admin navbar)
	app.ClientCountCache, app.ClientCountCacheCloser, err = initializeClientCountCache(
		ctx,
		app.Config,
	)
	if err != nil {
		return err
	}

	// Client Cache (caches OAuth client lookups by client_id)
	app.ClientCache, app.ClientCacheCloser, err = initializeClientCache(ctx, app.Config)
	if err != nil {
		return err
	}

	// Token Cache
	app.TokenCache, app.TokenCacheCloser, err = initializeTokenCache(ctx, app.Config)
	if err != nil {
		return err
	}

	// Redis (for rate limiting)
	app.RateLimitRedisClient, err = initializeRateLimitRedisClient(ctx, app.Config)
	if err != nil {
		return err
	}

	// Distributed cleanup lock (multi-pod: serialize DELETE jobs)
	app.CleanupLocker, err = initializeCleanupLocker(app.Config)
	if err != nil {
		return err
	}

	return nil
}

// initializeBusinessLayer sets up services
func (app *Application) initializeBusinessLayer() {
	// Audit service (required by other services)
	if app.Config.MetricsEnabled {
		services.SetAuditMetricsRegisterer(prometheus.DefaultRegisterer)
	}
	if app.Config.EnableAuditLogging {
		app.AuditService = services.NewAuditService(
			app.DB,
			app.Config.AuditLogBufferSize,
		)
	} else {
		app.AuditService = services.NewNoopAuditService()
	}

	// Initialize token provider (stored for JWKS handler)
	app.TokenProvider = initializeTokenProvider(app.Config)

	// Initialize all business services
	app.services = initializeServices(
		app.Config,
		app.DB,
		app.AuditService,
		app.MetricsRecorder,
		app.UserCache,
		app.ClientCountCache,
		app.ClientCache,
		app.TokenProvider,
		app.TokenCache,
	)
}

// initializeHTTPLayer sets up handlers, router, and server
func (app *Application) initializeHTTPLayer() {
	// OAuth setup
	oauthProviders := initializeOAuthProviders(app.Config)
	logOAuthProvidersStatus(oauthProviders)
	oauthHTTPClient := createOAuthHTTPClient(app.Config)

	// Handlers
	app.handlerSet = initializeHandlers(handlerDeps{
		cfg:            app.Config,
		services:       app.services,
		auditService:   app.AuditService,
		oauthProviders: oauthProviders,
		oauthClient:    oauthHTTPClient,
		metrics:        app.MetricsRecorder,
		templatesFS:    app.TemplatesFS,
		tokenProvider:  app.TokenProvider,
	})

	// Router
	app.Router = setupRouter(
		app.Config,
		app.DB,
		app.handlerSet,
		app.MetricsRecorder,
		app.AuditService,
		app.RateLimitRedisClient,
		app.TemplatesFS,
		oauthProviders,
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
	addClientCountCacheCleanupJob(m, app.ClientCountCache, app.Config)
	addClientCacheCleanupJob(m, app.ClientCache, app.Config)
	addTokenCacheCleanupJob(m, app.TokenCache, app.Config)
	addDatabaseShutdownJob(m, app.DB, app.Config)
	addAuditLogCleanupJob(m, app.Config, app.AuditService, app.CleanupLocker)
	addExpiredTokenCleanupJob(m, app.DB, app.Config, app.CleanupLocker)
	addCleanupLockerShutdownJob(m, app.CleanupLocker)
	addMetricsGaugeUpdateJob(m, app.Config, app.DB, app.MetricsRecorder, app.MetricsCache)

	// Wait for graceful shutdown
	<-m.Done()
}
