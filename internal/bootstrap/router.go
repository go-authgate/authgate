package bootstrap

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/handlers"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"

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
	prometheusMetrics core.Recorder,
	auditService *services.AuditService,
	rateLimitRedisClient *redis.Client,
	templatesFS embed.FS,
	oauthProviders map[string]*auth.OAuthProvider,
) *gin.Engine {
	// Setup Gin mode
	setupGinMode(cfg)
	r := gin.New()

	// Setup middleware
	r.Use(metrics.HTTPMetricsMiddleware(prometheusMetrics))
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(middleware.IPMiddleware())
	r.Use(middleware.SecurityHeaders(strings.HasPrefix(cfg.BaseURL, "https://")))

	// Setup session middleware
	setupSessionMiddleware(r, cfg)

	// Serve embedded static files
	serveStaticFiles(r, templatesFS, cfg.StaticCacheMaxAge)

	// Favicon endpoint
	r.GET("/favicon.ico", createFaviconHandler(templatesFS, cfg.StaticCacheMaxAge))

	// Health check endpoint
	r.GET("/health", createHealthCheckHandler(db))

	// Setup metrics endpoint
	setupMetricsEndpoint(r, cfg)

	// Setup rate limiting
	rateLimiters := setupRateLimiting(cfg, auditService, rateLimitRedisClient)

	// Setup all routes
	setupAllRoutes(r, cfg, h, rateLimiters, oauthProviders)

	// Log server startup info
	logServerStartup(cfg)

	return r
}

// setupSessionMiddleware configures session handling middleware
func setupSessionMiddleware(r *gin.Engine, cfg *config.Config) {
	sessionStore := cookie.NewStore([]byte(cfg.SessionSecret))
	opts := middleware.SessionOptions(cfg.SessionMaxAge, cfg.IsProduction)
	sessionStore.Options(opts)
	r.Use(sessions.Sessions("oauth_session", sessionStore))
	r.Use(middleware.SessionRememberMeMiddleware(cfg.SessionRememberMeMaxAge, cfg.IsProduction))
	r.Use(middleware.SessionIdleTimeout(cfg.SessionIdleTimeout))
	r.Use(middleware.SessionFingerprintMiddleware(cfg.SessionFingerprint, cfg.SessionFingerprintIP))
}

// serveStaticFiles configures static file serving with Cache-Control headers.
func serveStaticFiles(r *gin.Engine, templatesFS embed.FS, cacheMaxAge time.Duration) {
	staticSubFS, err := fs.Sub(templatesFS, "internal/templates/static")
	if err != nil {
		log.Fatalf("Failed to create static sub filesystem: %v", err)
	}
	serveStaticFilesFromFS(r, staticSubFS, cacheMaxAge)
}

// serveStaticFilesFromFS registers a static file handler on the router.
// Content-hashed files under /static/dist/ get immutable caching (1 year).
// Other static files use the configured cacheMaxAge duration.
// Cache-Control is only set on successful responses to avoid negative caching.
func serveStaticFilesFromFS(r *gin.Engine, staticFS fs.FS, cacheMaxAge time.Duration) {
	fileServer := http.StripPrefix("/static", http.FileServer(http.FS(staticFS)))

	// Pre-compute the non-dist Cache-Control value once at startup.
	var nonDistCacheControl string
	if cacheMaxAge > 0 {
		nonDistCacheControl = fmt.Sprintf("public, max-age=%d", int(cacheMaxAge.Seconds()))
	}

	handler := func(c *gin.Context) {
		// Set Cache-Control before serving so the file streams directly
		// to the client without buffering. We determine the header from
		// the URL path, and use a status-capturing wrapper to suppress
		// the header on error responses.
		path := c.Param("filepath")
		var cacheValue string
		if strings.HasPrefix(path, "/dist/") {
			cacheValue = "public, max-age=31536000, immutable"
		} else {
			cacheValue = nonDistCacheControl
		}

		w := &cacheControlWriter{
			ResponseWriter: c.Writer,
			cacheValue:     cacheValue,
		}
		c.Writer = w

		fileServer.ServeHTTP(c.Writer, c.Request)
	}
	r.GET("/static/*filepath", handler)
	r.HEAD("/static/*filepath", handler)
}

// cacheControlWriter injects a Cache-Control header only on successful responses.
// It wraps gin.ResponseWriter so the file server streams directly to the client
// without buffering the entire body (unlike httptest.NewRecorder).
type cacheControlWriter struct {
	gin.ResponseWriter
	cacheValue  string
	wroteHeader bool
}

func (w *cacheControlWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		if w.cacheValue != "" && (code == http.StatusOK || code == http.StatusPartialContent) {
			w.ResponseWriter.Header().Set("Cache-Control", w.cacheValue)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheControlWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
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
	oauthProviders map[string]*auth.OAuthProvider,
) {
	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/account/sessions")
	})

	// Documentation routes (public, optional auth for navbar)
	optionalAuth := middleware.OptionalAuth(h.userService)
	r.GET("/docs", optionalAuth, h.docs.ShowDocsIndex)
	r.GET("/docs/:slug", optionalAuth, h.docs.ShowDocsPage)

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

	// OIDC Discovery and JWKS (public, no auth required)
	r.GET("/.well-known/openid-configuration", h.oidc.Discovery)
	r.GET("/.well-known/jwks.json", h.jwks.JWKS)

	// OAuth API routes (public, called by CLI)
	oauth := r.Group("/oauth")
	if cfg.CORSEnabled {
		if len(cfg.CORSAllowedOrigins) == 0 {
			log.Println(
				"WARNING: CORS is enabled but CORS_ALLOWED_ORIGINS is empty — all cross-origin requests will be rejected",
			)
		}
		oauth.Use(middleware.CORSMiddleware(cfg))
	}
	{
		oauth.POST("/device/code", rateLimiters.deviceCode, h.device.DeviceCodeRequest)
		oauth.POST("/token", rateLimiters.token, h.token.Token)
		oauth.GET("/tokeninfo", h.token.TokenInfo)
		oauth.POST("/revoke", h.token.Revoke)
		oauth.POST("/register", rateLimiters.register, h.registration.Register)
		oauth.POST("/introspect", rateLimiters.introspect, h.token.Introspect)
		// OIDC UserInfo Endpoint (GET and POST per OIDC Core 1.0 §5.3)
		oauth.GET("/userinfo", h.oidc.UserInfo)
		oauth.POST("/userinfo", h.oidc.UserInfo)
	}

	// OAuth Authorization Code Flow (browser, requires login + CSRF)
	oauthProtected := r.Group("/oauth")
	oauthProtected.Use(middleware.RequireAuth(h.userService), middleware.CSRFMiddleware())
	{
		oauthProtected.GET("/authorize", h.authorization.ShowAuthorizePage)
		oauthProtected.POST("/authorize", h.authorization.HandleAuthorize)
	}

	// injectPendingCount adds the pending client count to context for admin users.
	// Applied to all authenticated route groups so the navbar badge is visible site-wide.
	injectPending := h.client.InjectPendingCount()

	// Protected routes (require login)
	protected := r.Group("")
	protected.Use(middleware.RequireAuth(h.userService), middleware.CSRFMiddleware(), injectPending)
	{
		protected.GET("/device", h.device.DevicePage)
		protected.POST("/device/verify", rateLimiters.deviceVerify, h.device.DeviceVerify)
	}

	// Account routes (require login)
	account := r.Group("/account")
	account.Use(middleware.RequireAuth(h.userService), middleware.CSRFMiddleware(), injectPending)
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

	// User apps area (all authenticated users, not admin-only)
	apps := r.Group("/apps")
	apps.Use(middleware.RequireAuth(h.userService), middleware.CSRFMiddleware(), injectPending)
	{
		apps.GET("", h.userClient.ShowMyAppsPage)
		apps.GET("/new", h.userClient.ShowCreateAppPage)
		apps.POST("", h.userClient.CreateApp)
		apps.GET("/:id", h.userClient.ShowAppPage)
		apps.GET("/:id/edit", h.userClient.ShowEditAppPage)
		apps.POST("/:id", h.userClient.UpdateApp)
		apps.POST("/:id/delete", h.userClient.DeleteApp)
		apps.POST("/:id/regenerate-secret", h.userClient.RegenerateAppSecret)
	}

	// Admin routes (require admin role)
	admin := r.Group("/admin")
	admin.Use(
		middleware.RequireAuth(h.userService),
		middleware.RequireAdmin(),
		middleware.CSRFMiddleware(),
		injectPending,
	)
	{
		admin.GET("/clients", h.client.ShowClientsPage)
		admin.GET("/clients/new", h.client.ShowCreateClientPage)
		admin.POST("/clients", h.client.CreateClient)
		admin.GET("/clients/:id", h.client.ViewClient)
		admin.GET("/clients/:id/edit", h.client.ShowEditClientPage)
		admin.POST("/clients/:id", h.client.UpdateClient)
		admin.POST("/clients/:id/delete", h.client.DeleteClient)
		admin.POST("/clients/:id/regenerate-secret", h.client.RegenerateSecret)
		admin.POST("/clients/:id/revoke-all", h.client.RevokeAllTokens)
		admin.GET("/clients/:id/authorizations", h.client.ListClientAuthorizations)
		admin.POST("/clients/:id/approve", h.client.ApproveClient)
		admin.POST("/clients/:id/reject", h.client.RejectClient)

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
	if len(providers) == 0 {
		return
	}
	oauthGroup := r.Group("/auth")
	oauthGroup.GET("/login/:provider", handler.LoginWithProvider)
	oauthGroup.GET("/callback/:provider", handler.OAuthCallback)
}

// createFaviconHandler creates favicon endpoint handler
// favicon godoc
//
//	@Summary		Favicon
//	@Description	Serve favicon.ico
//	@Tags			System
//	@Produce		image/x-icon
//	@Success		200	{file}	binary	"Favicon file"
//	@Router			/favicon.ico [get]
func createFaviconHandler(templatesFS embed.FS, cacheMaxAge time.Duration) gin.HandlerFunc {
	// Read favicon once at startup
	faviconData, err := templatesFS.ReadFile("internal/templates/static/images/favicon.ico")
	if err != nil {
		log.Printf("Warning: Failed to read favicon.ico: %v", err)
		// Return empty handler if favicon is missing
		return func(c *gin.Context) {
			c.Status(http.StatusNotFound)
		}
	}

	return createFaviconHandlerFromBytes(faviconData, cacheMaxAge)
}

// createFaviconHandlerFromBytes creates a favicon handler from pre-loaded bytes.
// Extracted so tests can call it directly without needing an embed.FS with a specific path.
func createFaviconHandlerFromBytes(faviconData []byte, cacheMaxAge time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cacheMaxAge > 0 {
			c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", int(cacheMaxAge.Seconds())))
		}
		c.Data(http.StatusOK, "image/x-icon", faviconData)
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
	log.Printf("Default user: admin (check authgate-credentials.txt for password if first run)")
	log.Printf("Default client: AuthGate CLI (check authgate-credentials.txt for client_id)")
}
