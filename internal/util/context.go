package util

import (
	"context"

	"github.com/go-authgate/authgate/internal/models"

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

// GetIPFromContext extracts the client IP address from the context
func GetIPFromContext(ctx context.Context) string {
	// Try to extract from Gin context first
	if ginCtx, ok := ctx.(*gin.Context); ok {
		return ginCtx.ClientIP()
	}

	// Try to get from context value (set by middleware)
	if ip, ok := ctx.Value("client_ip").(string); ok {
		return ip
	}

	return ""
}

// GetUsernameFromContext extracts the username from the user object in context
func GetUsernameFromContext(ctx context.Context) string {
	// Try to extract from Gin context first
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if userVal, exists := ginCtx.Get("user"); exists {
			if user, ok := userVal.(*models.User); ok {
				return user.Username
			}
		}
	}

	return ""
}
