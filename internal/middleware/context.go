package middleware

import (
	"github.com/gin-gonic/gin"
)

// IPMiddleware extracts client IP and stores it in the context
func IPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Gin's ClientIP() handles X-Forwarded-For and other headers
		c.Set("client_ip", c.ClientIP())
		c.Next()
	}
}
