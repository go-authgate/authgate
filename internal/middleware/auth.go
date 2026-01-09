package middleware

import (
	"net/http"

	"github.com/appleboy/authgate/internal/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionUserID = "user_id"
)

// RequireAuth is a middleware that requires the user to be logged in
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get(SessionUserID)

		if userID == nil {
			// Redirect to login with return URL
			redirectURL := c.Request.URL.String()
			c.Redirect(http.StatusFound, "/login?redirect="+redirectURL)
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}

// RequireAdmin is a middleware that requires the user to have admin role
// This middleware should be used after RequireAuth
func RequireAdmin(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "Unauthorized access",
			})
			c.Abort()
			return
		}

		user, err := userService.GetUserByID(userID.(string))
		if err != nil {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "User not found",
			})
			c.Abort()
			return
		}

		if !user.IsAdmin() {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "Admin access required",
			})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}
