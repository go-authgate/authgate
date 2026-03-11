package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Session constant aliases for convenience (canonical definitions in middleware package).
const (
	SessionUserID       = middleware.SessionUserID
	SessionUsername     = middleware.SessionUsername
	SessionLastActivity = middleware.SessionLastActivity
	SessionFingerprint  = middleware.SessionFingerprint
)

// buildOAuthProviderList converts the OAuth providers map into template-friendly display objects.
func buildOAuthProviderList(providers map[string]*auth.OAuthProvider) []templates.OAuthProvider {
	result := make([]templates.OAuthProvider, 0, len(providers))
	for _, p := range providers {
		result = append(result, templates.OAuthProvider{
			Name:        p.GetProvider(),
			DisplayName: p.GetDisplayName(),
		})
	}
	return result
}

type AuthHandler struct {
	userService                 *services.UserService
	baseURL                     string
	sessionFingerprintEnabled   bool
	sessionFingerprintIncludeIP bool
	metrics                     core.Recorder
}

func NewAuthHandler(
	us *services.UserService,
	baseURL string,
	fingerprintEnabled bool,
	fingerprintIncludeIP bool,
	m core.Recorder,
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
		// Already logged in, redirect to sessions page
		c.Redirect(http.StatusFound, "/account/sessions")
		return
	}

	redirectTo := c.Query("redirect")
	// Validate redirect URL security
	if !util.IsRedirectSafe(redirectTo, h.baseURL) {
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

	templates.RenderTempl(c, http.StatusOK, templates.LoginPage(templates.LoginPageProps{
		BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		Redirect:       redirectTo,
		Error:          errorMsg,
		OAuthProviders: buildOAuthProviderList(oauthProviders),
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

	// Validate redirect URL security, fall back to default
	if !util.IsRedirectSafe(redirectTo, h.baseURL) {
		redirectTo = "/account/sessions"
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

		templates.RenderTempl(
			c,
			http.StatusUnauthorized,
			templates.LoginPage(templates.LoginPageProps{
				BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				Error:          errorMsg,
				Redirect:       redirectTo,
				OAuthProviders: buildOAuthProviderList(oauthProviders),
			}),
		)
		return
	}

	// Record successful login
	duration := time.Since(start)
	authSource := user.AuthSource
	if authSource == "" {
		authSource = models.AuthSourceLocal
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
		fingerprint := middleware.GenerateFingerprint(
			clientIP,
			userAgent,
			h.sessionFingerprintIncludeIP,
		)
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

	c.Redirect(http.StatusFound, redirectTo)
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
