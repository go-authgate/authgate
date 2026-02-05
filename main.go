package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/client"
	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/handlers"
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
	"github.com/redis/go-redis/v9"
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
	db, err := store.New(cfg.DatabaseDriver, cfg.DatabaseDSN)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
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
	deviceService := services.NewDeviceService(db, cfg, auditService)
	tokenService := services.NewTokenService(
		db,
		cfg,
		deviceService,
		localTokenProvider,
		httpTokenProvider,
		cfg.TokenProviderMode,
		auditService,
	)
	clientService := services.NewClientService(db, auditService)

	// Initialize OAuth providers
	oauthProviders := initializeOAuthProviders(cfg)
	logOAuthProvidersStatus(oauthProviders)

	// Create HTTP client for OAuth requests
	oauthHTTPClient := createOAuthHTTPClient(cfg)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(userService)
	deviceHandler := handlers.NewDeviceHandler(deviceService, userService, cfg)
	tokenHandler := handlers.NewTokenHandler(tokenService, cfg)
	clientHandler := handlers.NewClientHandler(clientService)
	sessionHandler := handlers.NewSessionHandler(tokenService, userService)
	oauthHandler := handlers.NewOAuthHandler(oauthProviders, userService, oauthHTTPClient)
	auditHandler := handlers.NewAuditHandler(auditService)

	// Setup Gin
	setupGinMode(cfg)
	r := gin.Default()

	// Setup IP middleware (for audit logging)
	r.Use(util.IPMiddleware())

	// Setup session middleware
	sessionStore := cookie.NewStore([]byte(cfg.SessionSecret))
	sessionStore.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   cfg.IsProduction, // Require HTTPS in production
		SameSite: http.SameSiteStrictMode,
	})
	r.Use(sessions.Sessions("oauth_session", sessionStore))

	// Load embedded templates (including subdirectories)
	// Create a sub filesystem to strip the "internal/templates" prefix
	templateSubFS, err := fs.Sub(templatesFS, "internal/templates")
	if err != nil {
		log.Fatalf("Failed to create template sub filesystem: %v", err)
	}

	// Parse templates manually to preserve directory structure in names
	tmpl := template.New("")
	err = fs.WalkDir(templateSubFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}

		// Read the template file
		content, err := fs.ReadFile(templateSubFS, path)
		if err != nil {
			return err
		}

		// Parse with the full path as the name
		_, err = tmpl.New(path).Parse(string(content))
		return err
	})
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	r.SetHTMLTemplate(tmpl)

	// Serve embedded static files
	staticSubFS, err := fs.Sub(templatesFS, "internal/templates/static")
	if err != nil {
		log.Fatalf("Failed to create static sub filesystem: %v", err)
	}
	r.StaticFS("/static", http.FS(staticSubFS))

	// Health check endpoint
	r.GET("/health", createHealthCheckHandler(db))

	// Setup rate limiting
	rateLimiters, redisClient := setupRateLimiting(cfg, auditService)

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/device")
	})
	r.GET("/login", func(c *gin.Context) {
		authHandler.LoginPageWithOAuth(c, oauthProviders)
	})
	r.POST("/login", rateLimiters.login, authHandler.Login)
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
					if deleted, err := auditService.CleanupOldLogs(cfg.AuditLogRetention); err != nil {
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

// createOAuthHTTPClient creates an HTTP client for OAuth requests with retry support
func createOAuthHTTPClient(cfg *config.Config) *http.Client {
	if cfg.OAuthInsecureSkipVerify {
		log.Printf("WARNING: OAuth TLS verification is disabled (OAUTH_INSECURE_SKIP_VERIFY=true)")
	}

	client, err := httpclient.NewAuthClient(httpclient.AuthModeNone, "",
		httpclient.WithTimeout(cfg.OAuthTimeout),
		httpclient.WithInsecureSkipVerify(cfg.OAuthInsecureSkipVerify),
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
