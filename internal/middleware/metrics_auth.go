package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// MetricsAuthMiddleware creates a middleware that protects metrics endpoint with Bearer token
func MetricsAuthMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If no token configured, allow access (backwards compatibility)
		if token == "" {
			c.Next()
			return
		}

		// Extract Authorization header
		authHeader := c.GetHeader("Authorization")

		// Check if Authorization header is provided
		if authHeader == "" {
			c.Header("WWW-Authenticate", `Bearer realm="Metrics"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Bearer token required",
			})
			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.Header("WWW-Authenticate", `Bearer realm="Metrics"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Bearer token required",
			})
			return
		}

		// Extract token from "Bearer <token>"
		providedToken := strings.TrimPrefix(authHeader, "Bearer ")

		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
			c.Header("WWW-Authenticate", `Bearer realm="Metrics"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid token",
			})
			return
		}

		c.Next()
	}
}
