package middleware

import (
	"net/http"

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
