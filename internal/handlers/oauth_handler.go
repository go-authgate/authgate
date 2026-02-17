package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/metrics"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/templates"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// generateFingerprintOAuth creates a SHA256 hash from IP (optional) and User-Agent
func generateFingerprintOAuth(ip string, userAgent string, includeIP bool) string {
	data := userAgent
	if includeIP {
		data = ip + "|" + userAgent
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// OAuthHandler handles OAuth authentication
type OAuthHandler struct {
	providers                   map[string]*auth.OAuthProvider
	userService                 *services.UserService
	httpClient                  *http.Client // Custom HTTP client for OAuth requests
	sessionFingerprintEnabled   bool
	sessionFingerprintIncludeIP bool
	metrics                     metrics.MetricsRecorder
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	providers map[string]*auth.OAuthProvider,
	userService *services.UserService,
	httpClient *http.Client,
	fingerprintEnabled bool,
	fingerprintIncludeIP bool,
	m metrics.MetricsRecorder,
) *OAuthHandler {
	return &OAuthHandler{
		providers:                   providers,
		userService:                 userService,
		httpClient:                  httpClient,
		sessionFingerprintEnabled:   fingerprintEnabled,
		sessionFingerprintIncludeIP: fingerprintIncludeIP,
		metrics:                     m,
	}
}

// LoginWithProvider redirects user to OAuth provider
func (h *OAuthHandler) LoginWithProvider(c *gin.Context) {
	provider := c.Param("provider")

	// Check if provider exists
	oauthProvider, exists := h.providers[provider]
	if !exists {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Unsupported OAuth provider. The requested OAuth provider is not configured.",
			}),
		)
		return
	}

	// Generate state for CSRF protection
	state, err := generateRandomState(32)
	if err != nil {
		log.Printf("[OAuth] Failed to generate state: %v", err)
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Internal server error. Failed to initiate OAuth login.",
			}),
		)
		return
	}

	// Save state and redirect URL in session
	session := sessions.Default(c)
	session.Set("oauth_state", state)
	session.Set("oauth_provider", provider)

	// Save original redirect URL if present
	if redirect := c.Query("redirect"); redirect != "" {
		session.Set("oauth_redirect", redirect)
	}

	if err := session.Save(); err != nil {
		log.Printf("[OAuth] Failed to save session: %v", err)
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Internal server error. Failed to save session.",
			}),
		)
		return
	}

	// Redirect to OAuth provider
	authURL := oauthProvider.GetAuthURL(state)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// OAuthCallback handles OAuth provider callback
func (h *OAuthHandler) OAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	// Verify provider exists
	oauthProvider, exists := h.providers[provider]
	if !exists {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Invalid provider. OAuth provider not found.",
			}),
		)
		return
	}

	// Verify state (CSRF protection)
	session := sessions.Default(c)
	savedState := session.Get("oauth_state")
	savedProvider := session.Get("oauth_provider")

	if savedState == nil || savedProvider == nil {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Invalid session. OAuth session expired or invalid. Please try again.",
			}),
		)
		return
	}

	if state != savedState.(string) || provider != savedProvider.(string) {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Invalid state. CSRF validation failed. Please try again.",
			}),
		)
		return
	}

	// Use custom HTTP client for OAuth requests
	ctx := context.WithValue(c.Request.Context(), oauth2.HTTPClient, h.httpClient)

	// Exchange code for token
	token, err := oauthProvider.ExchangeCode(ctx, code)
	if err != nil {
		log.Printf("[OAuth] Failed to exchange code: %v", err)
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "OAuth error. Failed to exchange authorization code.",
			}),
		)
		return
	}

	// Get user info from provider
	userInfo, err := oauthProvider.GetUserInfo(ctx, token)
	if err != nil {
		log.Printf("[OAuth] Failed to get user info: %v", err)
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "OAuth error. Failed to retrieve user information from provider.",
			}),
		)
		return
	}

	// Authenticate or create user
	user, err := h.userService.AuthenticateWithOAuth(
		c.Request.Context(),
		provider,
		userInfo,
		token,
	)
	if err != nil {
		// Record failure
		h.metrics.RecordOAuthCallback(provider, false)

		log.Printf("[OAuth] Authentication failed: %v", err)

		// Handle specific errors
		if errors.Is(err, services.ErrOAuthAutoRegisterDisabled) {
			templates.RenderTempl(
				c,
				http.StatusForbidden,
				templates.ErrorPage(templates.ErrorPageProps{
					Error: "Registration Disabled. New account registration via OAuth is currently disabled. Please contact your administrator.",
				}),
			)
			return
		}

		// Generic error
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Authentication failed. Unable to authenticate your account at this time. Please try again later.",
			}),
		)
		return
	}

	// Record success
	h.metrics.RecordOAuthCallback(provider, true)

	// Clear OAuth session data
	session.Delete("oauth_state")
	session.Delete("oauth_provider")

	// Save user ID and username in session
	session.Set("user_id", user.ID)
	session.Set("username", user.Username)
	session.Set("last_activity", time.Now().Unix()) // Set initial last activity time

	// Set session fingerprint if enabled
	if h.sessionFingerprintEnabled {
		clientIP := c.GetString("client_ip") // Set by IPMiddleware
		userAgent := c.Request.UserAgent()
		fingerprint := generateFingerprintOAuth(clientIP, userAgent, h.sessionFingerprintIncludeIP)
		session.Set("session_fingerprint", fingerprint)
	}

	// Get redirect URL
	redirectURL := "/device"
	if savedRedirect := session.Get("oauth_redirect"); savedRedirect != nil {
		redirectURL = savedRedirect.(string)
		session.Delete("oauth_redirect")
	}

	if err := session.Save(); err != nil {
		log.Printf("[OAuth] Failed to save session: %v", err)
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Internal server error. Failed to save session.",
			}),
		)
		return
	}

	log.Printf("[OAuth] User authenticated: user=%s provider=%s", user.Username, provider)
	c.Redirect(http.StatusFound, redirectURL)
}

// generateRandomState generates a random state string for OAuth CSRF protection
func generateRandomState(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
