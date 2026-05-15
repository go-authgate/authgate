package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/go-authgate/authgate/internal/util"
)

// ContextKeyClientIP is the gin context key for the client IP address.
const ContextKeyClientIP = "client_ip"

// ContextKeySwaggerEnabled is the gin context key for the Swagger UI feature flag.
// InjectSwaggerEnabled sets it; buildNavbarProps reads it so templates can hide
// the Swagger links when /swagger is not registered.
const ContextKeySwaggerEnabled = "swagger_enabled"

// InjectSwaggerEnabled returns a middleware that stores the Swagger UI feature
// flag in the gin context on every request, so navbar/layout templates can show
// or hide Swagger links via NavbarProps.
func InjectSwaggerEnabled(enabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ContextKeySwaggerEnabled, enabled)
		c.Next()
	}
}

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
