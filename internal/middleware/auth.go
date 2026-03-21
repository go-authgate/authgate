package middleware

import (
	"errors"
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
	SessionRememberMe   = "remember_me"
)

// SessionOptions builds a sessions.Options with the project's standard cookie
// settings (Path "/", HttpOnly, SameSite Lax, Secure based on production flag).
func SessionOptions(maxAge int, isProduction bool) sessions.Options {
	return sessions.Options{
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
	}
}

// GenerateFingerprint creates a SHA256 hash from IP (optional) and User-Agent.
func GenerateFingerprint(ip, userAgent string, includeIP bool) string {
	data := userAgent
	if includeIP {
		data = ip + "|" + userAgent
	}
	return util.SHA256Hex(data)
}

// loadUserFromSession reads the user_id from the session, fetches the user, and
// populates "user_id", "user", and the request context.
// Returns (true, nil) on success, (false, nil) when there is no session or the
// user was deleted, and (false, err) on transient failures (DB down, etc.).
func loadUserFromSession(c *gin.Context, userService *services.UserService) (bool, error) {
	session := sessions.Default(c)
	userID := session.Get(SessionUserID)
	if userID == nil {
		return false, nil
	}
	userIDStr := userID.(string)
	user, err := userService.GetUserByID(userIDStr)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			// User no longer exists in DB — clear stale session to prevent redirect loops.
			// Return save errors so callers can 503 instead of redirect-looping.
			session.Clear()
			if saveErr := session.Save(); saveErr != nil {
				return false, saveErr
			}
			return false, nil
		}
		// Transient DB error — don't clear the session
		return false, err
	}
	c.Set("user_id", userIDStr)
	c.Set("user", user)
	c.Request = c.Request.WithContext(models.SetUserContext(c.Request.Context(), user))
	return true, nil
}

// OptionalAuth loads the user from session if logged in, but does not redirect if not.
// Use for public pages that show richer UI when authenticated.
func OptionalAuth(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, _ = loadUserFromSession(c, userService)
		c.Next()
	}
}

// RequireAuth is a middleware that requires the user to be logged in
func RequireAuth(userService *services.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		loaded, err := loadUserFromSession(c, userService)
		if err != nil {
			// Transient DB error — return 503 instead of redirecting to avoid loops
			c.String(
				http.StatusServiceUnavailable,
				"Service temporarily unavailable. Please try again.",
			)
			c.Abort()
			return
		}
		if !loaded {
			// Redirect to login with return URL
			redirectURL := c.Request.URL.String()
			c.Redirect(http.StatusFound, "/login?redirect="+url.QueryEscape(redirectURL))
			c.Abort()
			return
		}

		c.Next()
	}
}

// SessionRememberMeMiddleware overrides cookie MaxAge for "remember me" sessions.
// Must run after sessions.Sessions() and before SessionIdleTimeout.
func SessionRememberMeMiddleware(rememberMeMaxAge int, isProduction bool) gin.HandlerFunc {
	opts := SessionOptions(rememberMeMaxAge, isProduction)
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if remember, ok := session.Get(SessionRememberMe).(bool); ok && remember {
			session.Options(opts)
			// Save before c.Next() so the sliding-expiration cookie is sent
			// before the handler commits the response headers.
			_ = session.Save()
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
			// For "remember me" sessions, skip idle-timeout enforcement
			// but still update last activity and persist to the cookie.
			if remember, ok := session.Get(SessionRememberMe).(bool); ok && remember {
				session.Set(SessionLastActivity, time.Now().Unix())
				_ = session.Save()
				c.Next()
				return
			}

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
func RequireAdmin() gin.HandlerFunc {
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
