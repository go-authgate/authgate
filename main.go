package main

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/appleboy/authgate/config"
	"github.com/appleboy/authgate/handlers"
	"github.com/appleboy/authgate/middleware"
	"github.com/appleboy/authgate/services"
	"github.com/appleboy/authgate/store"
	"github.com/appleboy/graceful"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize store
	db, err := store.New(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize services
	userService := services.NewUserService(db)
	deviceService := services.NewDeviceService(db, cfg)
	tokenService := services.NewTokenService(db, cfg)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(userService)
	deviceHandler := handlers.NewDeviceHandler(deviceService, cfg)
	tokenHandler := handlers.NewTokenHandler(tokenService, cfg)

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

	// Load embedded templates
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
	r.SetHTMLTemplate(tmpl)

	// Serve embedded static files
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to create static sub filesystem: %v", err)
	}
	r.StaticFS("/static", http.FS(staticSubFS))

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/device")
	})
	r.GET("/login", authHandler.LoginPage)
	r.POST("/login", authHandler.Login)
	r.GET("/logout", authHandler.Logout)

	// OAuth API routes (public, called by CLI)
	oauth := r.Group("/oauth")
	{
		oauth.POST("/device/code", deviceHandler.DeviceCodeRequest)
		oauth.POST("/token", tokenHandler.Token)
		oauth.GET("/tokeninfo", tokenHandler.TokenInfo)
	}

	// Protected routes (require login)
	protected := r.Group("")
	protected.Use(middleware.RequireAuth())
	{
		protected.GET("/device", deviceHandler.DevicePage)
		protected.POST("/device/verify", deviceHandler.DeviceVerify)
	}

	// Start server
	log.Printf("OAuth Device Flow server starting on %s", cfg.ServerAddr)
	log.Printf("Verification URL: %s/device", cfg.BaseURL)
	log.Printf("Default user: admin / password123")
	log.Printf("Default client: AuthGate CLI (check logs for client_id)")

	// Create HTTP server
	srv := &http.Server{
		Addr:    cfg.ServerAddr,
		Handler: r,
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
