package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// OAuthHandler handles OAuth authentication
type OAuthHandler struct {
	providers   map[string]*auth.OAuthProvider
	userService *services.UserService
	httpClient  *http.Client // Custom HTTP client for OAuth requests
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	providers map[string]*auth.OAuthProvider,
	userService *services.UserService,
	httpClient *http.Client,
) *OAuthHandler {
	return &OAuthHandler{
		providers:   providers,
		userService: userService,
		httpClient:  httpClient,
	}
}

// LoginWithProvider redirects user to OAuth provider
func (h *OAuthHandler) LoginWithProvider(c *gin.Context) {
	provider := c.Param("provider")

	// Check if provider exists
	oauthProvider, exists := h.providers[provider]
	if !exists {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":   "Unsupported OAuth provider",
			"message": "The requested OAuth provider is not configured.",
		})
		return
	}

	// Generate state for CSRF protection
	state, err := generateRandomState(32)
	if err != nil {
		log.Printf("[OAuth] Failed to generate state: %v", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error":   "Internal server error",
			"message": "Failed to initiate OAuth login.",
		})
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
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error":   "Internal server error",
			"message": "Failed to save session.",
		})
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
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":   "Invalid provider",
			"message": "OAuth provider not found.",
		})
		return
	}

	// Verify state (CSRF protection)
	session := sessions.Default(c)
	savedState := session.Get("oauth_state")
	savedProvider := session.Get("oauth_provider")

	if savedState == nil || savedProvider == nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":   "Invalid session",
			"message": "OAuth session expired or invalid. Please try again.",
		})
		return
	}

	if state != savedState.(string) || provider != savedProvider.(string) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error":   "Invalid state",
			"message": "CSRF validation failed. Please try again.",
		})
		return
	}

	// Use custom HTTP client for OAuth requests
	ctx := context.WithValue(c.Request.Context(), oauth2.HTTPClient, h.httpClient)

	// Exchange code for token
	token, err := oauthProvider.ExchangeCode(ctx, code)
	if err != nil {
		log.Printf("[OAuth] Failed to exchange code: %v", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error":   "OAuth error",
			"message": "Failed to exchange authorization code.",
		})
		return
	}

	// Get user info from provider
	userInfo, err := oauthProvider.GetUserInfo(ctx, token)
	if err != nil {
		log.Printf("[OAuth] Failed to get user info: %v", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error":   "OAuth error",
			"message": "Failed to retrieve user information from provider.",
		})
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
		log.Printf("[OAuth] Authentication failed: %v", err)

		// Handle specific errors
		if errors.Is(err, services.ErrOAuthAutoRegisterDisabled) {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error":   "Registration Disabled",
				"message": "New account registration via OAuth is currently disabled. Please contact your administrator.",
			})
			return
		}

		// Generic error
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error":   "Authentication failed",
			"message": "Unable to authenticate your account at this time. Please try again later.",
		})
		return
	}

	// Clear OAuth session data
	session.Delete("oauth_state")
	session.Delete("oauth_provider")

	// Save user ID in session
	session.Set("user_id", user.ID)

	// Get redirect URL
	redirectURL := "/device"
	if savedRedirect := session.Get("oauth_redirect"); savedRedirect != nil {
		redirectURL = savedRedirect.(string)
		session.Delete("oauth_redirect")
	}

	if err := session.Save(); err != nil {
		log.Printf("[OAuth] Failed to save session: %v", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error":   "Internal server error",
			"message": "Failed to save session.",
		})
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
