package middleware

import (
	"time"

	"github.com/go-authgate/authgate/internal/config"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORSMiddleware returns a CORS middleware configured from application settings.
// It allows cross-origin requests from the configured origins to API endpoints.
func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins: cfg.CORSAllowedOrigins,
		AllowMethods: cfg.CORSAllowedMethods,
		AllowHeaders: cfg.CORSAllowedHeaders,
		MaxAge:       cfg.CORSMaxAge,

		// Expose standard OAuth response headers to browser JS
		ExposeHeaders: []string{"Content-Length", "Content-Type"},

		// Allow credentials (cookies, Authorization header) for token introspection
		AllowCredentials: true,
	})
}

// NewCORSConfig creates a cors.Config from application settings for testing purposes.
func NewCORSConfig(origins, methods, headers []string, maxAge time.Duration) cors.Config {
	return cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     methods,
		AllowHeaders:     headers,
		MaxAge:           maxAge,
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
	}
}
