package main

import (
	"log"

	"github.com/appleboy/authgate/config"
	"github.com/appleboy/authgate/handlers"
	"github.com/appleboy/authgate/middleware"
	"github.com/appleboy/authgate/services"
	"github.com/appleboy/authgate/store"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

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

	// Load templates
	r.LoadHTMLGlob("templates/*")

	// Static files
	r.Static("/static", "./static")

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
	log.Printf("Default client: cli-tool")

	if err := r.Run(cfg.ServerAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
