package util

import (
	"context"

	"github.com/gin-gonic/gin"
)

// GetIPFromContext extracts the client IP address from the context.
// It first attempts to extract from Gin context (via ClientIP method),
// then falls back to checking for "client_ip" value set by IPMiddleware.
// Returns empty string if IP cannot be determined.
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
