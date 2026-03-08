package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// OAuthHandler handles OAuth authentication
type OAuthHandler struct {
	providers                   map[string]*auth.OAuthProvider
	userService                 *services.UserService
	httpClient                  *http.Client // Custom HTTP client for OAuth requests
	baseURL                     string
	sessionFingerprintEnabled   bool
	sessionFingerprintIncludeIP bool
	metrics                     core.Recorder
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	providers map[string]*auth.OAuthProvider,
	userService *services.UserService,
	httpClient *http.Client,
	baseURL string,
	fingerprintEnabled bool,
	fingerprintIncludeIP bool,
	m core.Recorder,
) *OAuthHandler {
	return &OAuthHandler{
		providers:                   providers,
		userService:                 userService,
		httpClient:                  httpClient,
		baseURL:                     baseURL,
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
		renderErrorPage(
			c,
			http.StatusBadRequest,
			"Unsupported OAuth provider. The requested OAuth provider is not configured.",
		)
		return
	}

	// Generate state for CSRF protection
	state, err := generateRandomState(32)
	if err != nil {
		log.Printf("[OAuth] Failed to generate state: %v", err)
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Internal server error. Failed to initiate OAuth login.",
		)
		return
	}

	// Save state and redirect URL in session
	session := sessions.Default(c)
	session.Set("oauth_state", state)
	session.Set("oauth_provider", provider)

	// Save original redirect URL if present, validating it is safe first
	if redirect := c.Query("redirect"); redirect != "" && util.IsRedirectSafe(redirect, h.baseURL) {
		session.Set("oauth_redirect", redirect)
	}

	if err := session.Save(); err != nil {
		log.Printf("[OAuth] Failed to save session: %v", err)
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Internal server error. Failed to save session.",
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
		renderErrorPage(c, http.StatusBadRequest, "Invalid provider. OAuth provider not found.")
		return
	}

	if len(state) > maxStateLength {
		renderErrorPage(
			c,
			http.StatusBadRequest,
			"Invalid state parameter. State parameter exceeds maximum length.",
		)
		return
	}

	// Verify state (CSRF protection)
	session := sessions.Default(c)
	savedState := session.Get("oauth_state")
	savedProvider := session.Get("oauth_provider")

	if savedState == nil || savedProvider == nil {
		renderErrorPage(
			c,
			http.StatusBadRequest,
			"Invalid session. OAuth session expired or invalid. Please try again.",
		)
		return
	}

	if state != savedState.(string) || provider != savedProvider.(string) {
		renderErrorPage(
			c,
			http.StatusBadRequest,
			"Invalid state. CSRF validation failed. Please try again.",
		)
		return
	}

	// Use custom HTTP client for OAuth requests
	ctx := context.WithValue(c.Request.Context(), oauth2.HTTPClient, h.httpClient)

	// Exchange code for token
	token, err := oauthProvider.ExchangeCode(ctx, code)
	if err != nil {
		log.Printf("[OAuth] Failed to exchange code: %v", err)
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"OAuth error. Failed to exchange authorization code.",
		)
		return
	}

	// Get user info from provider
	userInfo, err := oauthProvider.GetUserInfo(ctx, token)
	if err != nil {
		log.Printf("[OAuth] Failed to get user info: %v", err)
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"OAuth error. Failed to retrieve user information from provider.",
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
			renderErrorPage(
				c,
				http.StatusForbidden,
				"Registration Disabled. New account registration via OAuth is currently disabled. Please contact your administrator.",
			)
			return
		}

		// Generic error
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Authentication failed. Unable to authenticate your account at this time. Please try again later.",
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
		fingerprint := generateFingerprint(clientIP, userAgent, h.sessionFingerprintIncludeIP)
		session.Set("session_fingerprint", fingerprint)
	}

	// Get redirect URL
	redirectURL := "/account/sessions"
	if savedRedirect := session.Get("oauth_redirect"); savedRedirect != nil {
		redirectURL = savedRedirect.(string)
		session.Delete("oauth_redirect")
	}

	if err := session.Save(); err != nil {
		log.Printf("[OAuth] Failed to save session: %v", err)
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Internal server error. Failed to save session.",
		)
		return
	}

	log.Printf("[OAuth] User authenticated: user=%s provider=%s", user.Username, provider)
	c.Redirect(http.StatusFound, redirectURL)
}

// generateRandomState returns a URL-safe base64-encoded string of nBytes random bytes.
func generateRandomState(nBytes int) (string, error) {
	b, err := util.CryptoRandomBytes(nBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
