package models

import (
	"context"

	"github.com/gin-gonic/gin"
)

// GetUsernameFromContext extracts the username from the user object in context.
// It attempts to extract from Gin context's "user" key set by RequireAuth middleware.
// Returns empty string if user cannot be determined.
func GetUsernameFromContext(ctx context.Context) string {
	// Try to extract from Gin context first
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if userVal, exists := ginCtx.Get("user"); exists {
			// Direct type assertion - no need to import models since we're IN models
			if user, ok := userVal.(*User); ok {
				return user.Username
			}
		}
	}

	return ""
}
