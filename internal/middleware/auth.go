package middleware

import (
	"net/http"
	"net/url"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionUserID       = "user_id"
	SessionUsername     = "username"
	SessionLastActivity = "last_activity"
	SessionFingerprint  = "session_fingerprint"
)

// GenerateFingerprint creates a SHA256 hash from IP (optional) and User-Agent.
func GenerateFingerprint(ip, userAgent string, includeIP bool) string {
	data := userAgent
	if includeIP {
		data = ip + "|" + userAgent
	}
	return util.SHA256Hex(data)
}

// loadUserFromSession reads the user_id from the session, fetches the user, and
// populates "user_id", "user", and the request context. Returns false if there
// is no session or the user cannot be loaded.
func loadUserFromSession(c *gin.Context, userService *services.UserService) bool {
	session := sessions.Default(c)
	userID := session.Get(SessionUserID)
	if userID == nil {
		return false
	}
	userIDStr := userID.(string)
	user, err := userService.GetUserByID(userIDStr)
	if err != nil {
		return false
	}
	c.Set("user_id", userIDStr)
	c.Set("user", user)
	c.Request = c.Request.WithContext(models.SetUserContext(c.Request.Context(), user))
	return true
}

// OptionalAuth loads the user from session if logged in, but does not redirect if not.
// Use for public pages that show richer UI when authenticated.
func OptionalAuth(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		loadUserFromSession(c, userService)
		c.Next()
	}
}

// RequireAuth is a middleware that requires the user to be logged in
func RequireAuth(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !loadUserFromSession(c, userService) {
			// Redirect to login with return URL
			redirectURL := c.Request.URL.String()
			c.Redirect(http.StatusFound, "/login?redirect="+url.QueryEscape(redirectURL))
			c.Abort()
			return
		}

		c.Next()
	}
}

// SessionFingerprintMiddleware validates session fingerprint to prevent session hijacking
// Checks User-Agent (and optionally IP) against stored fingerprint
func SessionFingerprintMiddleware(enabled, includeIP bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if fingerprinting is disabled
		if !enabled {
			c.Next()
			return
		}

		session := sessions.Default(c)
		userID := session.Get(SessionUserID)

		// Only check fingerprint for authenticated sessions
		if userID != nil {
			storedFingerprint := session.Get(SessionFingerprint)

			if storedFingerprint != nil {
				// Get current fingerprint
				clientIP := c.GetString(ContextKeyClientIP) // Set by IPMiddleware
				userAgent := c.Request.UserAgent()
				currentFingerprint := GenerateFingerprint(clientIP, userAgent, includeIP)

				// Compare fingerprints
				if storedFingerprint.(string) != currentFingerprint {
					// Fingerprint mismatch - possible session hijacking
					session.Clear()
					_ = session.Save()

					// Redirect to login with security warning
					redirectURL := c.Request.URL.String()
					c.Redirect(
						http.StatusFound,
						"/login?redirect="+url.QueryEscape(redirectURL)+"&error=session_invalid",
					)
					c.Abort()
					return
				}
			}
		}

		c.Next()
	}
}

// SessionIdleTimeout checks if the session has been idle for too long
// and clears it if necessary. Set idleTimeoutSeconds to 0 to disable.
func SessionIdleTimeout(idleTimeoutSeconds int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if idle timeout is disabled
		if idleTimeoutSeconds <= 0 {
			c.Next()
			return
		}

		session := sessions.Default(c)
		userID := session.Get(SessionUserID)

		// Only check idle timeout for authenticated sessions
		if userID != nil {
			lastActivity := session.Get(SessionLastActivity)

			if lastActivity != nil {
				lastActivityTime, ok := lastActivity.(int64)
				if ok {
					idleSeconds := time.Now().Unix() - lastActivityTime
					if idleSeconds > int64(idleTimeoutSeconds) {
						// Session idle timeout exceeded, clear session
						session.Clear()
						_ = session.Save()

						// Redirect to login with timeout message
						redirectURL := c.Request.URL.String()
						c.Redirect(
							http.StatusFound,
							"/login?redirect="+url.QueryEscape(
								redirectURL,
							)+"&error=session_timeout",
						)
						c.Abort()
						return
					}
				}
			}

			// Update last activity timestamp
			session.Set(SessionLastActivity, time.Now().Unix())
			_ = session.Save()
		}

		c.Next()
	}
}

// RequireAdmin is a middleware that requires the user to have admin role.
// This middleware should be used after RequireAuth, which already fetches
// and caches the user in the gin context via loadUserFromSession.
func RequireAdmin(_ *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		u, exists := c.Get("user")
		if !exists {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "Unauthorized access",
			})
			c.Abort()
			return
		}

		user, ok := u.(*models.User)
		if !ok || !user.IsAdmin() {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "Admin access required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
