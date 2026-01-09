package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	csrfTokenKey    = "csrf_token"
	csrfFormField   = "csrf_token"
	csrfHeaderField = "X-CSRF-Token"
)

// CSRFMiddleware provides CSRF protection for state-changing operations
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		// Generate token if not exists
		token := session.Get(csrfTokenKey)
		if token == nil {
			token = generateCSRFToken()
			session.Set(csrfTokenKey, token)
			if err := session.Save(); err != nil {
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{
					"error": "Failed to save CSRF token: " + err.Error(),
				})
				c.Abort()
				return
			}
		}

		// Make token available to templates
		c.Set(csrfTokenKey, token)

		// Validate token for state-changing methods
		if c.Request.Method == http.MethodPost ||
			c.Request.Method == http.MethodPut ||
			c.Request.Method == http.MethodDelete ||
			c.Request.Method == http.MethodPatch {
			// Get token from form or header
			submittedToken := c.PostForm(csrfFormField)
			if submittedToken == "" {
				submittedToken = c.GetHeader(csrfHeaderField)
			}

			// Validate token
			if submittedToken == "" || submittedToken != token {
				c.HTML(http.StatusForbidden, "error.html", gin.H{
					"error": "CSRF token validation failed. Please refresh the page and try again.",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// generateCSRFToken generates a random CSRF token
func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// This should never happen in practice, but if it does,
		// panic is acceptable as CSRF protection would be broken
		panic("failed to generate CSRF token: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// GetCSRFToken retrieves the CSRF token from the context
func GetCSRFToken(c *gin.Context) string {
	if token, exists := c.Get(csrfTokenKey); exists {
		if tokenStr, ok := token.(string); ok {
			return tokenStr
		}
	}
	return ""
}
