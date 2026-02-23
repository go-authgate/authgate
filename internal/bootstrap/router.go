package bootstrap

import (
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/handlers"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// setupRouter configures the Gin router with all routes and middleware
func setupRouter(
	cfg *config.Config,
	db *store.Store,
	h handlerSet,
	prometheusMetrics metrics.MetricsRecorder,
	auditService *services.AuditService,
	rateLimitRedisClient *redis.Client,
	templatesFS embed.FS,
) *gin.Engine {
	// Setup Gin mode
	setupGinMode(cfg)
	r := gin.New()

	// Setup middleware
	r.Use(metrics.HTTPMetricsMiddleware(prometheusMetrics))
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(util.IPMiddleware())

	// Setup session middleware
	setupSessionMiddleware(r, cfg)

	// Serve embedded static files
	serveStaticFiles(r, templatesFS)

	// Health check endpoint
	r.GET("/health", createHealthCheckHandler(db))

	// Setup metrics endpoint
	setupMetricsEndpoint(r, cfg)

	// Setup rate limiting
	rateLimiters := setupRateLimiting(cfg, auditService, rateLimitRedisClient)

	// Setup all routes
	setupAllRoutes(r, cfg, h, rateLimiters)

	// Log server startup info
	logServerStartup(cfg)

	return r
}

// setupSessionMiddleware configures session handling middleware
func setupSessionMiddleware(r *gin.Engine, cfg *config.Config) {
	sessionStore := cookie.NewStore([]byte(cfg.SessionSecret))
	sessionStore.Options(sessions.Options{
		Path:     "/",
		MaxAge:   cfg.SessionMaxAge,
		HttpOnly: true,
		Secure:   cfg.IsProduction,
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(sessions.Sessions("oauth_session", sessionStore))
	r.Use(middleware.SessionIdleTimeout(cfg.SessionIdleTimeout))
	r.Use(middleware.SessionFingerprintMiddleware(cfg.SessionFingerprint, cfg.SessionFingerprintIP))
}

// serveStaticFiles configures static file serving
func serveStaticFiles(r *gin.Engine, templatesFS embed.FS) {
	staticSubFS, err := fs.Sub(templatesFS, "internal/templates/static")
	if err != nil {
		log.Fatalf("Failed to create static sub filesystem: %v", err)
	}
	r.StaticFS("/static", http.FS(staticSubFS))
}

// setupMetricsEndpoint configures the Prometheus metrics endpoint
func setupMetricsEndpoint(r *gin.Engine, cfg *config.Config) {
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
}

// setupAllRoutes configures all application routes
func setupAllRoutes(
	r *gin.Engine,
	cfg *config.Config,
	h handlerSet,
	rateLimiters rateLimitMiddlewares,
) {
	// Get OAuth providers
	oauthProviders := initializeOAuthProviders(cfg)

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/device")
	})

	// Swagger documentation (development only)
	if !cfg.IsProduction {
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		log.Println("Swagger UI enabled at: http://localhost:8080/swagger/index.html")
	}

	// Login routes
	r.GET("/login", func(c *gin.Context) {
		h.auth.LoginPageWithOAuth(c, oauthProviders)
	})
	r.POST("/login", rateLimiters.login, func(c *gin.Context) {
		h.auth.Login(c, oauthProviders)
	})
	r.GET("/logout", h.auth.Logout)

	// OAuth routes (public)
	setupOAuthRoutes(r, oauthProviders, h.oauth)

	// OAuth API routes (public, called by CLI)
	oauth := r.Group("/oauth")
	{
		oauth.POST("/device/code", rateLimiters.deviceCode, h.device.DeviceCodeRequest)
		oauth.POST("/token", rateLimiters.token, h.token.Token)
		oauth.GET("/tokeninfo", h.token.TokenInfo)
		oauth.POST("/revoke", h.token.Revoke)
	}

	// OAuth Authorization Code Flow (browser, requires login + CSRF)
	oauthProtected := r.Group("/oauth")
	oauthProtected.Use(middleware.RequireAuth(h.userService), middleware.CSRFMiddleware())
	{
		oauthProtected.GET("/authorize", h.authorization.ShowAuthorizePage)
		oauthProtected.POST("/authorize", h.authorization.HandleAuthorize)
	}

	// Protected routes (require login)
	protected := r.Group("")
	protected.Use(middleware.RequireAuth(h.userService), middleware.CSRFMiddleware())
	{
		protected.GET("/device", h.device.DevicePage)
		protected.POST("/device/verify", rateLimiters.deviceVerify, h.device.DeviceVerify)
	}

	// Account routes (require login)
	account := r.Group("/account")
	account.Use(middleware.RequireAuth(h.userService), middleware.CSRFMiddleware())
	{
		account.GET("/sessions", h.session.ListSessions)
		account.POST("/sessions/:id/revoke", h.session.RevokeSession)
		account.POST("/sessions/:id/disable", h.session.DisableSession)
		account.POST("/sessions/:id/enable", h.session.EnableSession)
		account.POST("/sessions/revoke-all", h.session.RevokeAllSessions)
		// Authorization Code Flow consent management
		account.GET("/authorizations", h.authorization.ListAuthorizations)
		account.POST("/authorizations/:uuid/revoke", h.authorization.RevokeAuthorization)
	}

	// Admin routes (require admin role)
	admin := r.Group("/admin")
	admin.Use(
		middleware.RequireAuth(h.userService),
		middleware.RequireAdmin(h.userService),
		middleware.CSRFMiddleware(),
	)
	{
		admin.GET("/clients", h.client.ShowClientsPage)
		admin.GET("/clients/new", h.client.ShowCreateClientPage)
		admin.POST("/clients", h.client.CreateClient)
		admin.GET("/clients/:id", h.client.ViewClient)
		admin.GET("/clients/:id/edit", h.client.ShowEditClientPage)
		admin.POST("/clients/:id", h.client.UpdateClient)
		admin.POST("/clients/:id/delete", h.client.DeleteClient)
		admin.GET("/clients/:id/regenerate-secret", h.client.RegenerateSecret)
		admin.POST("/clients/:id/revoke-all", h.client.RevokeAllTokens)
		admin.GET("/clients/:id/authorizations", h.client.ListClientAuthorizations)

		// Audit log routes (HTML pages)
		admin.GET("/audit", h.audit.ShowAuditLogsPage)
		admin.GET("/audit/export", h.audit.ExportAuditLogs)

		// Audit log API routes (JSON)
		admin.GET("/audit/api", h.audit.ListAuditLogs)
		admin.GET("/audit/api/stats", h.audit.GetAuditLogStats)
	}
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

// logServerStartup logs server startup information
func logServerStartup(cfg *config.Config) {
	log.Printf("Authentication mode: %s", cfg.AuthMode)
	log.Printf("OAuth Device Flow server starting on %s", cfg.ServerAddr)
	log.Printf("Verification URL: %s/device", cfg.BaseURL)
	log.Printf("  (Tip: Add ?user_code=XXXX-XXXX to pre-fill the code)")
	log.Printf("Default user: admin (check logs for password if first run)")
	log.Printf("Default client: AuthGate CLI (check logs for client_id)")
}
