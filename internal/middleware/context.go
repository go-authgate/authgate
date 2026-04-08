package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/go-authgate/authgate/internal/util"
)

// ContextKeyClientIP is the gin context key for the client IP address.
const ContextKeyClientIP = "client_ip"

// RequestContextMiddleware extracts client IP and HTTP request metadata
// (User-Agent, path, method) and stores them in the request context for
// downstream services (e.g. audit logging).
func RequestContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		// Gin's ClientIP() handles X-Forwarded-For and other headers
		c.Set(ContextKeyClientIP, clientIP)

		// Store IP and request metadata in request context for services layer
		ctx := util.SetIPContext(c.Request.Context(), clientIP)
		ctx = util.SetRequestMetadataContext(
			ctx,
			c.Request.UserAgent(),
			c.Request.URL.Path,
			c.Request.Method,
		)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
