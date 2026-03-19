package middleware

import (
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
