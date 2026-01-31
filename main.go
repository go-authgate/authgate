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
	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/handlers"
	"github.com/appleboy/authgate/internal/middleware"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/token"
	"github.com/appleboy/authgate/internal/version"
	"github.com/appleboy/go-httpclient"
	retry "github.com/appleboy/go-httpretry"

	"github.com/appleboy/graceful"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

//go:embed internal/templates/*
var templatesFS embed.FS

//go:embed internal/static/*
var staticFS embed.FS

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

	// Initialize authentication providers
	localProvider := auth.NewLocalAuthProvider(db)

	var httpAPIProvider *auth.HTTPAPIAuthProvider
	if cfg.AuthMode == config.AuthModeHTTPAPI {
		// Create retry client for HTTP API authentication
		authRetryClient, err := createRetryClient(
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
		httpAPIProvider = auth.NewHTTPAPIAuthProvider(cfg, authRetryClient)
		log.Printf("HTTP API authentication enabled: %s", cfg.HTTPAPIURL)
	}

	// Initialize token providers
	localTokenProvider := token.NewLocalTokenProvider(cfg)

	var httpTokenProvider *token.HTTPTokenProvider
	if cfg.TokenProviderMode == config.TokenProviderModeHTTPAPI {
		// Create retry client for token API
		tokenRetryClient, err := createRetryClient(
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
		httpTokenProvider = token.NewHTTPTokenProvider(cfg, tokenRetryClient)
		log.Printf("HTTP API token provider enabled: %s", cfg.TokenAPIURL)
	}

	// Initialize services
	userService := services.NewUserService(
		db,
		localProvider,
		httpAPIProvider,
		cfg.AuthMode,
		cfg.OAuthAutoRegister,
	)
	deviceService := services.NewDeviceService(db, cfg)
	tokenService := services.NewTokenService(
		db,
		cfg,
		localTokenProvider,
		httpTokenProvider,
		cfg.TokenProviderMode,
	)
	clientService := services.NewClientService(db)

	// Initialize OAuth providers
	oauthProviders := initializeOAuthProviders(cfg)
	if len(oauthProviders) > 0 {
		log.Printf("OAuth providers enabled: %v", getProviderNames(oauthProviders))
	}

	// Create HTTP client for OAuth requests
	oauthHTTPClient := createOAuthHTTPClient(cfg)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(userService)
	deviceHandler := handlers.NewDeviceHandler(deviceService, userService, cfg)
	tokenHandler := handlers.NewTokenHandler(tokenService, cfg)
	clientHandler := handlers.NewClientHandler(clientService)
	sessionHandler := handlers.NewSessionHandler(tokenService)
	oauthHandler := handlers.NewOAuthHandler(oauthProviders, userService, oauthHTTPClient)

	// Setup Gin
	r := gin.Default()

	// Setup session middleware
	sessionStore := cookie.NewStore([]byte(cfg.SessionSecret))
	sessionStore.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: 2,     // Lax
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
	staticSubFS, err := fs.Sub(staticFS, "internal/static")
	if err != nil {
		log.Fatalf("Failed to create static sub filesystem: %v", err)
	}
	r.StaticFS("/static", http.FS(staticSubFS))

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		// Check database connection
		if err := db.Health(); err == nil {
			c.JSON(http.StatusOK, gin.H{
				"status":   "healthy",
				"database": "connected",
			})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "unhealthy",
			"database": "disconnected",
		})
	})

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/device")
	})
	r.GET("/login", func(c *gin.Context) {
		authHandler.LoginPageWithOAuth(c, oauthProviders)
	})
	r.POST("/login", authHandler.Login)
	r.GET("/logout", authHandler.Logout)

	// OAuth routes (public)
	if len(oauthProviders) > 0 {
		oauthGroup := r.Group("/auth")
		{
			oauthGroup.GET("/login/:provider", oauthHandler.LoginWithProvider)
			oauthGroup.GET("/callback/:provider", oauthHandler.OAuthCallback)
		}
	}

	// OAuth API routes (public, called by CLI)
	oauth := r.Group("/oauth")
	{
		oauth.POST("/device/code", deviceHandler.DeviceCodeRequest)
		oauth.POST("/token", tokenHandler.Token)
		oauth.GET("/tokeninfo", tokenHandler.TokenInfo)
		oauth.POST("/revoke", tokenHandler.Revoke)
	}

	// Protected routes (require login)
	protected := r.Group("")
	protected.Use(middleware.RequireAuth(), middleware.CSRFMiddleware())
	{
		protected.GET("/device", deviceHandler.DevicePage)
		protected.POST("/device/verify", deviceHandler.DeviceVerify)
	}

	// Account routes (require login)
	account := r.Group("/account")
	account.Use(middleware.RequireAuth(), middleware.CSRFMiddleware())
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
		middleware.RequireAuth(),
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

	// Add shutdown job
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
	if cfg.GitHubOAuthEnabled {
		if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" {
			log.Printf("Warning: GitHub OAuth enabled but CLIENT_ID or CLIENT_SECRET missing")
		} else {
			providers["github"] = auth.NewGitHubProvider(auth.OAuthProviderConfig{
				ClientID:     cfg.GitHubClientID,
				ClientSecret: cfg.GitHubClientSecret,
				RedirectURL:  cfg.GitHubOAuthRedirectURL,
				Scopes:       cfg.GitHubOAuthScopes,
			})
			log.Printf("GitHub OAuth configured: redirect=%s", cfg.GitHubOAuthRedirectURL)
		}
	}

	// Gitea OAuth
	if cfg.GiteaOAuthEnabled {
		if cfg.GiteaURL == "" || cfg.GiteaClientID == "" || cfg.GiteaClientSecret == "" {
			log.Printf("Warning: Gitea OAuth enabled but URL, CLIENT_ID or CLIENT_SECRET missing")
		} else {
			providers["gitea"] = auth.NewGiteaProvider(auth.OAuthProviderConfig{
				ClientID:     cfg.GiteaClientID,
				ClientSecret: cfg.GiteaClientSecret,
				RedirectURL:  cfg.GiteaOAuthRedirectURL,
				Scopes:       cfg.GiteaOAuthScopes,
			}, cfg.GiteaURL)
			log.Printf("Gitea OAuth configured: server=%s redirect=%s", cfg.GiteaURL, cfg.GiteaOAuthRedirectURL)
		}
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

// createRetryClient creates an HTTP client with retry support and authentication
func createRetryClient(
	authMode, authSecret string,
	timeout time.Duration,
	insecureSkipVerify bool,
	maxRetries int,
	retryDelay, maxRetryDelay time.Duration,
	authHeader string,
) (*retry.Client, error) { // Create HTTP client with automatic authentication
	client, err := httpclient.NewAuthClient(
		authMode,
		authSecret,
		httpclient.WithTimeout(timeout),
		httpclient.WithHeaderName(authHeader),
		httpclient.WithInsecureSkipVerify(insecureSkipVerify),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth client: %w", err)
	}

	// Wrap with retry client
	retryClient, err := retry.NewRealtimeClient(
		retry.WithHTTPClient(client),
		retry.WithMaxRetries(maxRetries),
		retry.WithInitialRetryDelay(retryDelay),
		retry.WithMaxRetryDelay(maxRetryDelay),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create retry client: %w", err)
	}

	return retryClient, nil
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
