//	@title			AuthGate API
//	@version		1.0
//	@description	OAuth 2.0 Device Authorization Grant (RFC 8628) server
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	API Support
//	@contact.url	https://github.com/appleboy/authgate
//	@contact.email	appleboy.tw@gmail.com

//	@license.name	MIT
//	@license.url	https://github.com/appleboy/authgate/blob/main/LICENSE

//	@host		localhost:8080
//	@BasePath	/

//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Type "Bearer" followed by a space and JWT token.

//	@securityDefinitions.apikey	SessionAuth
//	@in							cookie
//	@name						oauth_session
//	@description				Session cookie for authenticated users

package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/cache"
	"github.com/appleboy/authgate/internal/client"
	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/handlers"
	"github.com/appleboy/authgate/internal/metrics"
	"github.com/appleboy/authgate/internal/middleware"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/token"
	"github.com/appleboy/authgate/internal/util"
	"github.com/appleboy/authgate/internal/version"

	"github.com/appleboy/go-httpclient"
	"github.com/appleboy/graceful"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/appleboy/authgate/api" // swagger docs
)

//go:embed internal/templates/*
var templatesFS embed.FS

func main() {
	// Define flags
	showVersion := flag.Bool("version", false, "Show version information")
	flag.BoolVar(showVersion, "v", false, "Show version information (shorthand)")
	flag.Usage = printUsage
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		version.PrintVersion()
		os.Exit(0)
	}

	// Check if command is provided
	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	// Handle subcommands
	switch args[0] {
	case "server":
		runServer()
	default:
		fmt.Printf("Unknown command: %s\n\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("Usage: %s [OPTIONS] COMMAND\n\n", os.Args[0])
	fmt.Println("OAuth 2.0 Device Authorization Grant server")
	fmt.Println("\nCommands:")
	fmt.Println("  server    Start the OAuth server")
	fmt.Println("\nOptions:")
	fmt.Println("  -v, --version    Show version information")
	fmt.Println("  -h, --help       Show this help message")
}

func runServer() {
	// Load configuration
	cfg := config.Load()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Validate authentication configuration
	if err := validateAuthConfig(cfg); err != nil {
		log.Fatalf("Invalid authentication configuration: %v", err)
	}

	// Validate token provider configuration
	if err := validateTokenProviderConfig(cfg); err != nil {
		log.Fatalf("Invalid token provider configuration: %v", err)
	}

	// Initialize store
	db, err := store.New(cfg.DatabaseDriver, cfg.DatabaseDSN, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize metrics
	prometheusMetrics := metrics.Init(cfg.MetricsEnabled)
	if cfg.MetricsEnabled {
		log.Println("Prometheus metrics initialized")
	} else {
		log.Println("Metrics disabled (using noop implementation)")
	}

	// Initialize metrics cache (only if metrics and gauge updates are enabled)
	var metricsCache cache.Cache
	var metricsCacheCloser func() error
	if cfg.MetricsEnabled && cfg.MetricsGaugeUpdateEnabled {
		var err error
		switch cfg.MetricsCacheType {
		case config.MetricsCacheTypeRedisAside:
			metricsCache, err = cache.NewRueidisAsideCache(
				cfg.RedisAddr,
				cfg.RedisPassword,
				cfg.RedisDB,
				"metrics:",
				cfg.MetricsCacheClientTTL,
				cfg.MetricsCacheSizePerConn,
			)
			if err != nil {
				log.Fatalf("Failed to initialize redis-aside metrics cache: %v", err)
			}
			log.Printf(
				"Metrics cache: redis-aside (addr=%s, db=%d, client_ttl=%s, cache_size_per_conn=%dMB)",
				cfg.RedisAddr,
				cfg.RedisDB,
				cfg.MetricsCacheClientTTL,
				cfg.MetricsCacheSizePerConn,
			)
		case config.MetricsCacheTypeRedis:
			metricsCache, err = cache.NewRueidisCache(
				cfg.RedisAddr,
				cfg.RedisPassword,
				cfg.RedisDB,
				"metrics:",
			)
			if err != nil {
				log.Fatalf("Failed to initialize redis metrics cache: %v", err)
			}
			log.Printf("Metrics cache: redis (addr=%s, db=%d)", cfg.RedisAddr, cfg.RedisDB)
		default: // memory
			metricsCache = cache.NewMemoryCache()
			log.Println("Metrics cache: memory (single instance only)")
		}
		metricsCacheCloser = metricsCache.Close
	}

	// Initialize audit service
	auditService := services.NewAuditService(db, cfg.EnableAuditLogging, cfg.AuditLogBufferSize)

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

	// Initialize OAuth providers
	oauthProviders := initializeOAuthProviders(cfg)
	logOAuthProvidersStatus(oauthProviders)

	// Create HTTP client for OAuth requests
	oauthHTTPClient := createOAuthHTTPClient(cfg)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(
		userService,
		cfg.BaseURL,
		cfg.SessionFingerprint,
		cfg.SessionFingerprintIP,
		prometheusMetrics,
	)
	deviceHandler := handlers.NewDeviceHandler(deviceService, userService, cfg)
	tokenHandler := handlers.NewTokenHandler(tokenService, cfg)
	clientHandler := handlers.NewClientHandler(clientService)
	sessionHandler := handlers.NewSessionHandler(tokenService, userService)
	oauthHandler := handlers.NewOAuthHandler(
		oauthProviders,
		userService,
		oauthHTTPClient,
		cfg.SessionFingerprint,
		cfg.SessionFingerprintIP,
		prometheusMetrics,
	)
	auditHandler := handlers.NewAuditHandler(auditService)

	// Setup Gin
	setupGinMode(cfg)
	r := gin.New()
	// Setup Prometheus metrics middleware (must be before other routes)
	r.Use(metrics.HTTPMetricsMiddleware(prometheusMetrics))
	r.Use(gin.Logger(), gin.Recovery())

	// Setup IP middleware (for audit logging)
	r.Use(util.IPMiddleware())

	// Setup session middleware
	sessionStore := cookie.NewStore([]byte(cfg.SessionSecret))
	sessionStore.Options(sessions.Options{
		Path:     "/",
		MaxAge:   cfg.SessionMaxAge, // Configurable session lifetime (default: 1 hour)
		HttpOnly: true,
		Secure:   cfg.IsProduction,     // Require HTTPS in production
		SameSite: http.SameSiteLaxMode, // Lax mode required for OAuth callbacks
	})
	r.Use(sessions.Sessions("oauth_session", sessionStore))

	// Setup session security middleware
	r.Use(middleware.SessionIdleTimeout(cfg.SessionIdleTimeout))
	r.Use(middleware.SessionFingerprintMiddleware(cfg.SessionFingerprint, cfg.SessionFingerprintIP))

	// Serve embedded static files
	staticSubFS, err := fs.Sub(templatesFS, "internal/templates/static")
	if err != nil {
		log.Fatalf("Failed to create static sub filesystem: %v", err)
	}
	r.StaticFS("/static", http.FS(staticSubFS))

	// Health check endpoint
	r.GET("/health", createHealthCheckHandler(db))

	// Prometheus metrics endpoint (with optional authentication)
	switch {
	case !cfg.MetricsEnabled:
		log.Printf("Prometheus metrics disabled")
	case cfg.MetricsToken != "":
		log.Printf("Prometheus metrics enabled at /metrics with Bearer token authentication")
		r.GET(
			"/metrics",
			middleware.MetricsAuthMiddleware(cfg.MetricsToken),
			gin.WrapH(promhttp.Handler()),
		)
	default:
		log.Printf("Prometheus metrics enabled at /metrics (no authentication)")
		r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}

	// Setup rate limiting
	rateLimiters, redisClient := setupRateLimiting(cfg, auditService)

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/device")
	})

	// Swagger documentation (development only)
	if !cfg.IsProduction {
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		log.Println("Swagger UI enabled at: http://localhost:8080/swagger/index.html")
	}

	r.GET("/login", func(c *gin.Context) {
		authHandler.LoginPageWithOAuth(c, oauthProviders)
	})
	r.POST("/login", rateLimiters.login, func(c *gin.Context) {
		authHandler.Login(c, oauthProviders)
	})
	r.GET("/logout", authHandler.Logout)

	// OAuth routes (public)
	setupOAuthRoutes(r, oauthProviders, oauthHandler)

	// OAuth API routes (public, called by CLI)
	oauth := r.Group("/oauth")
	{
		oauth.POST("/device/code", rateLimiters.deviceCode, deviceHandler.DeviceCodeRequest)
		oauth.POST("/token", rateLimiters.token, tokenHandler.Token)
		oauth.GET("/tokeninfo", tokenHandler.TokenInfo)
		oauth.POST("/revoke", tokenHandler.Revoke)
	}

	// Protected routes (require login)
	protected := r.Group("")
	protected.Use(middleware.RequireAuth(userService), middleware.CSRFMiddleware())
	{
		protected.GET("/device", deviceHandler.DevicePage)
		protected.POST("/device/verify", rateLimiters.deviceVerify, deviceHandler.DeviceVerify)
	}

	// Account routes (require login)
	account := r.Group("/account")
	account.Use(middleware.RequireAuth(userService), middleware.CSRFMiddleware())
	{
		account.GET("/sessions", sessionHandler.ListSessions)
		account.POST("/sessions/:id/revoke", sessionHandler.RevokeSession)
		account.POST("/sessions/:id/disable", sessionHandler.DisableSession)
		account.POST("/sessions/:id/enable", sessionHandler.EnableSession)
		account.POST("/sessions/revoke-all", sessionHandler.RevokeAllSessions)
	}

	// Admin routes (require admin role)
	admin := r.Group("/admin")
	admin.Use(
		middleware.RequireAuth(userService),
		middleware.RequireAdmin(userService),
		middleware.CSRFMiddleware(),
	)
	{
		admin.GET("/clients", clientHandler.ShowClientsPage)
		admin.GET("/clients/new", clientHandler.ShowCreateClientPage)
		admin.POST("/clients", clientHandler.CreateClient)
		admin.GET("/clients/:id", clientHandler.ViewClient)
		admin.GET("/clients/:id/edit", clientHandler.ShowEditClientPage)
		admin.POST("/clients/:id", clientHandler.UpdateClient)
		admin.POST("/clients/:id/delete", clientHandler.DeleteClient)
		admin.GET("/clients/:id/regenerate-secret", clientHandler.RegenerateSecret)

		// Audit log routes (HTML pages)
		admin.GET("/audit", auditHandler.ShowAuditLogsPage)
		admin.GET("/audit/export", auditHandler.ExportAuditLogs)

		// Audit log API routes (JSON)
		admin.GET("/audit/api", auditHandler.ListAuditLogs)
		admin.GET("/audit/api/stats", auditHandler.GetAuditLogStats)
	}

	// Start server
	log.Printf("Authentication mode: %s", cfg.AuthMode)
	log.Printf("OAuth Device Flow server starting on %s", cfg.ServerAddr)
	log.Printf("Verification URL: %s/device", cfg.BaseURL)
	log.Printf("  (Tip: Add ?user_code=XXXX-XXXX to pre-fill the code)")
	log.Printf("Default user: admin (check logs for password if first run)")
	log.Printf("Default client: AuthGate CLI (check logs for client_id)")

	// Create HTTP server
	srv := &http.Server{
		Addr:              cfg.ServerAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Create graceful manager
	m := graceful.NewManager()

	// Add server as a running job
	m.AddRunningJob(func(ctx context.Context) error {
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		}()
		<-ctx.Done()
		return nil
	})

	// Add shutdown job for HTTP server
	m.AddShutdownJob(func() error {
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
			return err
		}

		log.Println("Server exited")
		return nil
	})

	// Add shutdown job for Redis client (if used)
	if redisClient != nil {
		m.AddShutdownJob(func() error {
			log.Println("Closing Redis connection...")
			if err := redisClient.Close(); err != nil {
				log.Printf("Error closing Redis client: %v", err)
				return err
			}
			log.Println("Redis connection closed")
			return nil
		})
	}

	// Add shutdown job for audit service
	m.AddShutdownJob(func() error {
		log.Println("Shutting down audit service...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := auditService.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down audit service: %v", err)
			return err
		}
		return nil
	})

	// Add cleanup job for old audit logs (runs daily)
	if cfg.EnableAuditLogging && cfg.AuditLogRetention > 0 {
		m.AddRunningJob(func(ctx context.Context) error {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()

			// Run cleanup immediately on startup
			if deleted, err := auditService.CleanupOldLogs(cfg.AuditLogRetention); err != nil {
				log.Printf("Failed to cleanup old audit logs: %v", err)
			} else if deleted > 0 {
				log.Printf("Cleaned up %d old audit logs", deleted)
			}

			for {
				select {
				case <-ticker.C:
					if deleted, err := auditService.CleanupOldLogs(
						cfg.AuditLogRetention,
					); err != nil {
						log.Printf("Failed to cleanup old audit logs: %v", err)
					} else if deleted > 0 {
						log.Printf("Cleaned up %d old audit logs", deleted)
					}
				case <-ctx.Done():
					return nil
				}
			}
		})
	}

	// Add metrics gauge update job
	if cfg.MetricsEnabled && cfg.MetricsGaugeUpdateEnabled {
		m.AddRunningJob(func(ctx context.Context) error {
			ticker := time.NewTicker(cfg.MetricsGaugeUpdateInterval)
			defer ticker.Stop()

			// Create cache wrapper
			cacheWrapper := metrics.NewMetricsCacheWrapper(db, metricsCache)

			// Update immediately on startup
			updateGaugeMetricsWithCache(
				ctx,
				cacheWrapper,
				prometheusMetrics,
				cfg.MetricsGaugeUpdateInterval,
			)

			for {
				select {
				case <-ticker.C:
					updateGaugeMetricsWithCache(
						ctx,
						cacheWrapper,
						prometheusMetrics,
						cfg.MetricsGaugeUpdateInterval,
					)
				case <-ctx.Done():
					return nil
				}
			}
		})
	}

	// Add cache cleanup on shutdown
	if metricsCacheCloser != nil {
		m.AddShutdownJob(func() error {
			if err := metricsCacheCloser(); err != nil {
				log.Printf("Error closing metrics cache: %v", err)
			} else {
				log.Println("Metrics cache closed")
			}
			return nil
		})
	}

	// Wait for graceful shutdown
	<-m.Done()
}

// validateAuthConfig checks that required config is present for selected auth mode
func validateAuthConfig(cfg *config.Config) error {
	switch cfg.AuthMode {
	case config.AuthModeHTTPAPI:
		if cfg.HTTPAPIURL == "" {
			return errors.New("HTTP_API_URL is required when AUTH_MODE=http_api")
		}
	case config.AuthModeLocal:
		// No additional validation needed
	default:
		return fmt.Errorf("invalid AUTH_MODE: %s (must be: local, http_api)", cfg.AuthMode)
	}
	return nil
}

// validateTokenProviderConfig checks that required config is present for selected token provider mode
func validateTokenProviderConfig(cfg *config.Config) error {
	switch cfg.TokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		if cfg.TokenAPIURL == "" {
			return errors.New("TOKEN_API_URL is required when TOKEN_PROVIDER_MODE=http_api")
		}
	case config.TokenProviderModeLocal:
		// No additional validation needed
	default:
		return fmt.Errorf(
			"invalid TOKEN_PROVIDER_MODE: %s (must be: local, http_api)",
			cfg.TokenProviderMode,
		)
	}
	return nil
}

// initializeOAuthProviders initializes configured OAuth providers
func initializeOAuthProviders(cfg *config.Config) map[string]*auth.OAuthProvider {
	providers := make(map[string]*auth.OAuthProvider)

	// GitHub OAuth
	switch {
	case !cfg.GitHubOAuthEnabled:
		// Skip GitHub OAuth
	case cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "":
		log.Printf("Warning: GitHub OAuth enabled but CLIENT_ID or CLIENT_SECRET missing")
	default:
		providers["github"] = auth.NewGitHubProvider(auth.OAuthProviderConfig{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  cfg.GitHubOAuthRedirectURL,
			Scopes:       cfg.GitHubOAuthScopes,
		})
		log.Printf("GitHub OAuth configured: redirect=%s", cfg.GitHubOAuthRedirectURL)
	}

	// Gitea OAuth
	switch {
	case !cfg.GiteaOAuthEnabled:
		// Skip Gitea OAuth
	case cfg.GiteaURL == "" || cfg.GiteaClientID == "" || cfg.GiteaClientSecret == "":
		log.Printf("Warning: Gitea OAuth enabled but URL, CLIENT_ID or CLIENT_SECRET missing")
	default:
		providers["gitea"] = auth.NewGiteaProvider(auth.OAuthProviderConfig{
			ClientID:     cfg.GiteaClientID,
			ClientSecret: cfg.GiteaClientSecret,
			RedirectURL:  cfg.GiteaOAuthRedirectURL,
			Scopes:       cfg.GiteaOAuthScopes,
		}, cfg.GiteaURL)
		log.Printf(
			"Gitea OAuth configured: server=%s redirect=%s",
			cfg.GiteaURL,
			cfg.GiteaOAuthRedirectURL,
		)
	}

	// Microsoft Entra ID OAuth
	switch {
	case !cfg.MicrosoftOAuthEnabled:
		// Skip Microsoft OAuth
	case cfg.MicrosoftClientID == "" || cfg.MicrosoftClientSecret == "":
		log.Printf("Warning: Microsoft OAuth enabled but CLIENT_ID or CLIENT_SECRET missing")
	default:
		providers["microsoft"] = auth.NewMicrosoftProvider(auth.OAuthProviderConfig{
			ClientID:     cfg.MicrosoftClientID,
			ClientSecret: cfg.MicrosoftClientSecret,
			RedirectURL:  cfg.MicrosoftOAuthRedirectURL,
			Scopes:       cfg.MicrosoftOAuthScopes,
		}, cfg.MicrosoftTenantID)
		log.Printf(
			"Microsoft OAuth configured: tenant=%s redirect=%s",
			cfg.MicrosoftTenantID,
			cfg.MicrosoftOAuthRedirectURL,
		)
	}

	return providers
}

// getProviderNames returns a list of provider names
func getProviderNames(providers map[string]*auth.OAuthProvider) []string {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	return names
}

// createOAuthHTTPClient creates an HTTP client for OAuth requests with optimized connection pool
func createOAuthHTTPClient(cfg *config.Config) *http.Client {
	if cfg.OAuthInsecureSkipVerify {
		log.Printf("WARNING: OAuth TLS verification is disabled (OAUTH_INSECURE_SKIP_VERIFY=true)")
	}

	// Create optimized transport with connection pool settings
	transport := client.CreateOptimizedTransport(cfg.OAuthInsecureSkipVerify)

	client, err := httpclient.NewAuthClient(httpclient.AuthModeNone, "",
		httpclient.WithTimeout(cfg.OAuthTimeout),
		httpclient.WithTransport(transport),
	)
	if err != nil {
		log.Fatalf("Failed to create OAuth HTTP client: %v", err)
	}

	return client
}

// logOAuthProvidersStatus logs enabled OAuth providers
func logOAuthProvidersStatus(providers map[string]*auth.OAuthProvider) {
	if len(providers) > 0 {
		log.Printf("OAuth providers enabled: %v", getProviderNames(providers))
	}
}

// createHealthCheckHandler creates health check endpoint handler
// healthCheck godoc
//
//	@Summary		Health check
//	@Description	Check server and database health status
//	@Tags			System
//	@Produce		json
//	@Success		200	{object}	object{status=string,database=string}	"Service is healthy"
//	@Failure		503	{object}	object{status=string,database=string}	"Service is unhealthy"
//	@Router			/health [get]
func createHealthCheckHandler(db *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		switch err := db.Health(); err {
		case nil:
			c.JSON(http.StatusOK, gin.H{
				"status":   "healthy",
				"database": "connected",
			})
		default:
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":   "unhealthy",
				"database": "disconnected",
			})
		}
	}
}

// rateLimitMiddlewares holds rate limiting middlewares for different endpoints
type rateLimitMiddlewares struct {
	login        gin.HandlerFunc
	deviceCode   gin.HandlerFunc
	token        gin.HandlerFunc
	deviceVerify gin.HandlerFunc
}

// setupRateLimiting configures rate limiting middlewares based on configuration
// Returns rate limit middlewares and optional Redis client (needs cleanup on shutdown)
func setupRateLimiting(
	cfg *config.Config,
	auditService *services.AuditService,
) (rateLimitMiddlewares, *redis.Client) {
	// Return no-op middlewares when rate limiting is disabled
	noOpMiddleware := func(c *gin.Context) { c.Next() }
	disabledLimiters := rateLimitMiddlewares{
		login:        noOpMiddleware,
		deviceCode:   noOpMiddleware,
		token:        noOpMiddleware,
		deviceVerify: noOpMiddleware,
	}

	switch {
	case !cfg.EnableRateLimit:
		return disabledLimiters, nil
	default:
		return createRateLimiters(cfg, auditService)
	}
}

// createRateLimiters creates rate limiting middlewares for all endpoints
// Returns rate limit middlewares and optional shared Redis client
func createRateLimiters(
	cfg *config.Config,
	auditService *services.AuditService,
) (rateLimitMiddlewares, *redis.Client) {
	log.Printf("Rate limiting enabled (store: %s)", cfg.RateLimitStore)

	storeType := middleware.RateLimitStoreType(cfg.RateLimitStore)
	var sharedRedisClient *redis.Client

	// Create shared Redis client for all limiters when using Redis store
	if storeType == middleware.RateLimitStoreRedis {
		var err error
		sharedRedisClient, err = middleware.CreateRedisClient(
			cfg.RedisAddr,
			cfg.RedisPassword,
			cfg.RedisDB,
		)
		if err != nil {
			log.Fatalf("Failed to create shared Redis client: %v", err)
		}
		log.Printf("Redis rate limiting configured: %s (DB: %d)", cfg.RedisAddr, cfg.RedisDB)
	} else {
		log.Printf("In-memory rate limiting configured (single instance only)")
	}

	createLimiter := func(requestsPerMinute int, endpoint string) gin.HandlerFunc {
		limiter, err := middleware.NewRateLimiter(middleware.RateLimitConfig{
			RequestsPerMinute: requestsPerMinute,
			StoreType:         storeType,
			RedisClient:       sharedRedisClient, // Shared client (nil for memory store)
			RedisAddr:         cfg.RedisAddr,
			RedisPassword:     cfg.RedisPassword,
			RedisDB:           cfg.RedisDB,
			CleanupInterval:   cfg.RateLimitCleanupInterval,
			AuditService:      auditService, // Add audit service for logging
		})
		if err != nil {
			log.Fatalf("Failed to create rate limiter for %s: %v", endpoint, err)
		}
		return limiter
	}

	return rateLimitMiddlewares{
		login:        createLimiter(cfg.LoginRateLimit, "/login"),
		deviceCode:   createLimiter(cfg.DeviceCodeRateLimit, "/oauth/device/code"),
		token:        createLimiter(cfg.TokenRateLimit, "/oauth/token"),
		deviceVerify: createLimiter(cfg.DeviceVerifyRateLimit, "/device/verify"),
	}, sharedRedisClient
}

// setupOAuthRoutes configures OAuth authentication routes
func setupOAuthRoutes(
	r *gin.Engine,
	providers map[string]*auth.OAuthProvider,
	handler *handlers.OAuthHandler,
) {
	switch {
	case len(providers) == 0:
		return
	default:
		oauthGroup := r.Group("/auth")
		oauthGroup.GET("/login/:provider", handler.LoginWithProvider)
		oauthGroup.GET("/callback/:provider", handler.OAuthCallback)
	}
}

// initializeHTTPAPIAuthProvider creates HTTP API auth provider when configured
func initializeHTTPAPIAuthProvider(cfg *config.Config) *auth.HTTPAPIAuthProvider {
	switch cfg.AuthMode {
	case config.AuthModeHTTPAPI:
		authRetryClient, err := client.CreateRetryClient(
			cfg.HTTPAPIAuthMode,
			cfg.HTTPAPIAuthSecret,
			cfg.HTTPAPITimeout,
			cfg.HTTPAPIInsecureSkipVerify,
			cfg.HTTPAPIMaxRetries,
			cfg.HTTPAPIRetryDelay,
			cfg.HTTPAPIMaxRetryDelay,
			cfg.HTTPAPIAuthHeader,
		)
		if err != nil {
			log.Fatalf("Failed to create HTTP API auth client: %v", err)
		}
		log.Printf("HTTP API authentication enabled: %s", cfg.HTTPAPIURL)
		return auth.NewHTTPAPIAuthProvider(cfg, authRetryClient)
	default:
		return nil
	}
}

// initializeHTTPTokenProvider creates HTTP token provider when configured
func initializeHTTPTokenProvider(cfg *config.Config) *token.HTTPTokenProvider {
	switch cfg.TokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		tokenRetryClient, err := client.CreateRetryClient(
			cfg.TokenAPIAuthMode,
			cfg.TokenAPIAuthSecret,
			cfg.TokenAPITimeout,
			cfg.TokenAPIInsecureSkipVerify,
			cfg.TokenAPIMaxRetries,
			cfg.TokenAPIRetryDelay,
			cfg.TokenAPIMaxRetryDelay,
			cfg.TokenAPIAuthHeader,
		)
		if err != nil {
			log.Fatalf("Failed to create token API client: %v", err)
		}
		log.Printf("HTTP API token provider enabled: %s", cfg.TokenAPIURL)
		return token.NewHTTPTokenProvider(cfg, tokenRetryClient)
	default:
		return nil
	}
}

// setupGinMode sets Gin mode based on environment configuration
func setupGinMode(cfg *config.Config) {
	mode := ginModeMap[cfg.IsProduction]
	gin.SetMode(mode)
	log.Printf("Gin mode: %s", ginModeLogMessage[cfg.IsProduction])
}

var ginModeMap = map[bool]string{
	true:  gin.ReleaseMode,
	false: gin.DebugMode,
}

var ginModeLogMessage = map[bool]string{
	true:  "Release (production)",
	false: "Debug (development)",
}

// errorLogger handles rate-limited error logging
type errorLogger struct {
	lastErrorTimes  map[string]time.Time
	rateLimitWindow time.Duration
}

// newErrorLogger creates a new error logger with rate limiting
func newErrorLogger() *errorLogger {
	return &errorLogger{
		lastErrorTimes:  make(map[string]time.Time),
		rateLimitWindow: 5 * time.Minute, // Log at most once per 5 minutes per operation
	}
}

// logIfNeeded logs an error only if rate limit allows
func (e *errorLogger) logIfNeeded(operation string, err error) {
	now := time.Now()
	lastTime, exists := e.lastErrorTimes[operation]

	if !exists || now.Sub(lastTime) >= e.rateLimitWindow {
		log.Printf("Database query failed for %s: %v (further errors will be suppressed for %v)",
			operation, err, e.rateLimitWindow)
		e.lastErrorTimes[operation] = now
	}
}

var gaugeErrorLogger = newErrorLogger()

// updateGaugeMetricsWithCache updates gauge metrics using a cache-backed store.
// This reduces database load in multi-instance deployments by caching query results.
// The cache TTL should match the update interval to ensure consistent behavior.
func updateGaugeMetricsWithCache(
	ctx context.Context,
	cacheWrapper *metrics.MetricsCacheWrapper,
	m metrics.MetricsRecorder,
	cacheTTL time.Duration,
) {
	// Update active access tokens count
	activeAccessTokens, err := cacheWrapper.GetActiveTokensCount(ctx, "access", cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_access_tokens")
		gaugeErrorLogger.logIfNeeded("count_access_tokens", err)
	} else {
		m.SetActiveTokensCount("access", int(activeAccessTokens))
	}

	// Update active refresh tokens count
	activeRefreshTokens, err := cacheWrapper.GetActiveTokensCount(ctx, "refresh", cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_refresh_tokens")
		gaugeErrorLogger.logIfNeeded("count_refresh_tokens", err)
	} else {
		m.SetActiveTokensCount("refresh", int(activeRefreshTokens))
	}

	// Update active device codes count
	totalDeviceCodes, err := cacheWrapper.GetTotalDeviceCodesCount(ctx, cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_total_device_codes")
		gaugeErrorLogger.logIfNeeded("count_total_device_codes", err)
		totalDeviceCodes = 0
	}

	pendingDeviceCodes, err := cacheWrapper.GetPendingDeviceCodesCount(ctx, cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_pending_device_codes")
		gaugeErrorLogger.logIfNeeded("count_pending_device_codes", err)
		pendingDeviceCodes = 0
	}

	m.SetActiveDeviceCodesCount(int(totalDeviceCodes), int(pendingDeviceCodes))
}
