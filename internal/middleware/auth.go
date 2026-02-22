package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/appleboy/authgate/internal/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionUserID       = "user_id"
	SessionLastActivity = "last_activity"
	SessionFingerprint  = "session_fingerprint"
)

// generateFingerprint creates a SHA256 hash from IP (optional) and User-Agent
func generateFingerprint(ip string, userAgent string, includeIP bool) string {
	data := userAgent
	if includeIP {
		data = ip + "|" + userAgent
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// RequireAuth is a middleware that requires the user to be logged in
func RequireAuth(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get(SessionUserID)

		if userID == nil {
			// Redirect to login with return URL
			redirectURL := c.Request.URL.String()
			c.Redirect(http.StatusFound, "/login?redirect="+url.QueryEscape(redirectURL))
			c.Abort()
			return
		}

		c.Set("user_id", userID)

		// Load user object for audit logging and other purposes
		user, err := userService.GetUserByID(userID.(string))
		if err == nil {
			c.Set("user", user)
		}

		c.Next()
	}
}

// SessionFingerprintMiddleware validates session fingerprint to prevent session hijacking
// Checks User-Agent (and optionally IP) against stored fingerprint
func SessionFingerprintMiddleware(enabled bool, includeIP bool) gin.HandlerFunc {
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
				clientIP := c.GetString("client_ip") // Set by IPMiddleware
				userAgent := c.Request.UserAgent()
				currentFingerprint := generateFingerprint(clientIP, userAgent, includeIP)

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
