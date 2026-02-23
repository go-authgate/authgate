package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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

const (
	SessionUserID       = "user_id"
	SessionUsername     = "username"
	SessionLastActivity = "last_activity"
	SessionFingerprint  = "session_fingerprint"
)

// isRedirectSafe validates that a redirect URL is safe to use.
// It only allows:
// 1. Relative paths starting with "/" but not "//"
// 2. Absolute URLs that match the baseURL host
func isRedirectSafe(redirectURL, baseURL string) bool {
	// Empty redirect is safe (will use default)
	if redirectURL == "" {
		return true
	}

	// Must not contain newlines or carriage returns (header injection)
	if strings.ContainsAny(redirectURL, "\r\n") {
		return false
	}

	// Check if it's a relative path
	if strings.HasPrefix(redirectURL, "/") {
		// Reject protocol-relative URLs like "//evil.com"
		if strings.HasPrefix(redirectURL, "//") {
			return false
		}
		// Reject backslash variations like "/\evil.com"
		if strings.Contains(redirectURL, "\\") {
			return false
		}
		// Valid relative path
		return true
	}

	// If it's an absolute URL, parse and validate against baseURL
	parsedRedirect, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	// Reject javascript:, data:, and other non-http(s) schemes
	if parsedRedirect.Scheme != "" && parsedRedirect.Scheme != "http" &&
		parsedRedirect.Scheme != "https" {
		return false
	}

	// If there's a host specified, it must match baseURL
	if parsedRedirect.Host != "" {
		parsedBase, err := url.Parse(baseURL)
		if err != nil {
			return false
		}
		// Host must match exactly
		if parsedRedirect.Host != parsedBase.Host {
			return false
		}
	}

	return true
}

type AuthHandler struct {
	userService                 *services.UserService
	baseURL                     string
	sessionFingerprintEnabled   bool
	sessionFingerprintIncludeIP bool
	metrics                     metrics.MetricsRecorder
}

func NewAuthHandler(
	us *services.UserService,
	baseURL string,
	fingerprintEnabled bool,
	fingerprintIncludeIP bool,
	m metrics.MetricsRecorder,
) *AuthHandler {
	return &AuthHandler{
		userService:                 us,
		baseURL:                     baseURL,
		sessionFingerprintEnabled:   fingerprintEnabled,
		sessionFingerprintIncludeIP: fingerprintIncludeIP,
		metrics:                     m,
	}
}

// LoginPage renders the login page
func (h *AuthHandler) LoginPage(c *gin.Context) {
	h.LoginPageWithOAuth(c, nil)
}

// LoginPageWithOAuth renders the login page with OAuth providers
func (h *AuthHandler) LoginPageWithOAuth(
	c *gin.Context,
	oauthProviders map[string]*auth.OAuthProvider,
) {
	session := sessions.Default(c)
	if session.Get(SessionUserID) != nil {
		// Already logged in, redirect to device page
		c.Redirect(http.StatusFound, "/device")
		return
	}

	redirectTo := c.Query("redirect")
	// Validate redirect URL security
	if !isRedirectSafe(redirectTo, h.baseURL) {
		redirectTo = ""
	}

	// Prepare error message
	errorMsg := ""
	if errorParam := c.Query("error"); errorParam != "" {
		switch errorParam {
		case "session_timeout":
			errorMsg = "Your session has expired due to inactivity. Please sign in again."
		case "session_invalid":
			errorMsg = "Your session is invalid or may have been accessed from a different device. Please sign in again."
		default:
			errorMsg = errorParam
		}
	}

	// Prepare OAuth provider data for template
	providers := []templates.OAuthProvider{}
	for _, provider := range oauthProviders {
		providers = append(providers, templates.OAuthProvider{
			Name:        provider.GetProvider(),
			DisplayName: provider.GetDisplayName(),
		})
	}

	templates.RenderTempl(c, http.StatusOK, templates.LoginPage(templates.LoginPageProps{
		BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		Redirect:       redirectTo,
		Error:          errorMsg,
		OAuthProviders: providers,
	}))
}

// Login handles the login form submission
func (h *AuthHandler) Login(c *gin.Context,
	oauthProviders map[string]*auth.OAuthProvider,
) {
	start := time.Now()
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirectTo := c.PostForm("redirect")

	// Validate redirect URL security
	if !isRedirectSafe(redirectTo, h.baseURL) {
		redirectTo = ""
	}

	user, err := h.userService.Authenticate(c.Request.Context(), username, password)
	if err != nil {
		// Record failed login
		duration := time.Since(start)
		h.metrics.RecordLogin("local", false)
		h.metrics.RecordAuthAttempt("local", false, duration)

		var errorMsg string

		// Check for specific error types
		if errors.Is(err, services.ErrUsernameConflict) {
			errorMsg = "Username conflict with existing user. Please contact administrator."
		} else {
			errorMsg = "Invalid username or password"
		}

		// Prepare OAuth provider data for template
		providers := []templates.OAuthProvider{}
		for _, provider := range oauthProviders {
			providers = append(providers, templates.OAuthProvider{
				Name:        provider.GetProvider(),
				DisplayName: provider.GetDisplayName(),
			})
		}

		templates.RenderTempl(
			c,
			http.StatusUnauthorized,
			templates.LoginPage(templates.LoginPageProps{
				BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				Error:          errorMsg,
				Redirect:       redirectTo,
				OAuthProviders: providers,
			}),
		)
		return
	}

	// Record successful login
	duration := time.Since(start)
	authSource := user.AuthSource
	if authSource == "" {
		authSource = "local"
	}
	h.metrics.RecordLogin(authSource, true)
	h.metrics.RecordAuthAttempt(authSource, true, duration)

	// Set session
	session := sessions.Default(c)
	session.Set(SessionUserID, user.ID)
	session.Set(SessionUsername, user.Username)
	session.Set(SessionLastActivity, time.Now().Unix()) // Set initial last activity time

	// Set session fingerprint if enabled
	if h.sessionFingerprintEnabled {
		clientIP := c.GetString("client_ip") // Set by IPMiddleware
		userAgent := c.Request.UserAgent()
		fingerprint := generateFingerprint(clientIP, userAgent, h.sessionFingerprintIncludeIP)
		session.Set(SessionFingerprint, fingerprint)
	}

	if err := session.Save(); err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.LoginPage(templates.LoginPageProps{
				BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				Error:     "Failed to create session",
			}),
		)
		return
	}

	// Redirect
	if redirectTo != "" {
		c.Redirect(http.StatusFound, redirectTo)
	} else {
		c.Redirect(http.StatusFound, "/device")
	}
}

// Logout clears the session and redirects to login
func (h *AuthHandler) Logout(c *gin.Context) {
	session := sessions.Default(c)

	// Calculate session duration if available
	var sessionDuration time.Duration
	if createdAtUnix := session.Get(SessionLastActivity); createdAtUnix != nil {
		if createdAtInt64, ok := createdAtUnix.(int64); ok {
			createdAt := time.Unix(createdAtInt64, 0)
			sessionDuration = time.Since(createdAt)
		}
	}

	session.Clear()
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save session",
		})
		return
	}

	// Record logout
	h.metrics.RecordLogout(sessionDuration)

	c.Redirect(http.StatusFound, "/login")
}
