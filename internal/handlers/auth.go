package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/middleware"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/templates"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionUserID   = "user_id"
	SessionUsername = "username"
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
	userService *services.UserService
	baseURL     string
}

func NewAuthHandler(us *services.UserService, baseURL string) *AuthHandler {
	return &AuthHandler{
		userService: us,
		baseURL:     baseURL,
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
		Error:          c.Query("error"),
		OAuthProviders: providers,
	}))
}

// Login handles the login form submission
func (h *AuthHandler) Login(c *gin.Context,
	oauthProviders map[string]*auth.OAuthProvider,
) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirectTo := c.PostForm("redirect")

	// Validate redirect URL security
	if !isRedirectSafe(redirectTo, h.baseURL) {
		redirectTo = ""
	}

	user, err := h.userService.Authenticate(c.Request.Context(), username, password)
	if err != nil {
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

	// Set session
	session := sessions.Default(c)
	session.Set(SessionUserID, user.ID)
	session.Set(SessionUsername, user.Username)
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
	session.Clear()
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save session",
		})
		return
	}
	c.Redirect(http.StatusFound, "/login")
}
