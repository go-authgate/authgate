package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/go-authgate/authgate/internal/util"
)

// ContextKeyClientIP is the gin context key for the client IP address.
const ContextKeyClientIP = "client_ip"

// IPMiddleware extracts client IP and stores it in the context
func IPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		// Gin's ClientIP() handles X-Forwarded-For and other headers
		c.Set(ContextKeyClientIP, clientIP)

		// Also store in request context for services layer
		c.Request = c.Request.WithContext(util.SetIPContext(c.Request.Context(), clientIP))

		c.Next()
	}
}
