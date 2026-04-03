package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-gonic/gin"
)

// authzSuccessMessages maps success query parameter keys to user-facing messages.
var authzSuccessMessages = map[string]string{
	"revoked": "Application access has been revoked successfully.",
}

// authzErrorMessages maps error query parameter keys to user-facing messages.
var authzErrorMessages = map[string]string{
	"not_found":    "Authorization not found.",
	"server_error": "An error occurred while processing your request. Please try again.",
}

// AuthorizationHandler manages the OAuth 2.0 Authorization Code Flow consent pages
// and the user's authorized-applications management UI.
type AuthorizationHandler struct {
	authorizationService *services.AuthorizationService
	tokenService         *services.TokenService
	userService          *services.UserService
	config               *config.Config
}

func NewAuthorizationHandler(
	as *services.AuthorizationService,
	ts *services.TokenService,
	us *services.UserService,
	cfg *config.Config,
) *AuthorizationHandler {
	return &AuthorizationHandler{
		authorizationService: as,
		tokenService:         ts,
		userService:          us,
		config:               cfg,
	}
}

// ShowAuthorizePage renders the OAuth consent page (GET /oauth/authorize).
// Requires the user to be logged in (enforced by RequireAuth middleware).
func (h *AuthorizationHandler) ShowAuthorizePage(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if !h.validateStateAndNonce(c, redirectURI, state, nonce) {
		return
	}

	// Validate the authorization request parameters
	req, err := h.authorizationService.ValidateAuthorizationRequest(
		clientID, redirectURI, responseType, scope, codeChallenge, codeChallengeMethod, nonce,
	)
	if err != nil {
		h.redirectWithError(c, redirectURI, state, oauthErrorCode(err), err.Error())
		return
	}

	userIDStr := getUserIDFromContext(c)

	// Retrieve the logged-in user for display
	user, err := h.userService.GetUserByID(userIDStr)
	if err != nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// If ConsentRemember is enabled and the user has already consented to all
	// requested scopes, skip the consent page and issue a code immediately.
	if h.config.ConsentRemember {
		existing, _ := h.authorizationService.GetUserAuthorization(userIDStr, req.Client.ID)
		if existing != nil && util.IsScopeSubset(existing.Scopes, req.Scopes) {
			h.issueCodeAndRedirect(c, req, userIDStr, state)
			return
		}
	}

	// Render the consent page
	templates.RenderTempl(c, http.StatusOK, templates.AuthorizePage(templates.AuthorizePageProps{
		BaseProps:           templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps:         buildNavbarProps(c, user, ""),
		Username:            user.Username,
		ClientID:            req.Client.ClientID,
		ClientName:          req.Client.ClientName,
		ClientDescription:   req.Client.Description,
		RedirectURI:         req.RedirectURI,
		Scopes:              req.Scopes,
		ScopeList:           strings.Fields(req.Scopes),
		State:               state,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}))
}

// HandleAuthorize processes the user's consent decision (POST /oauth/authorize).
// Requires the user to be logged in and a valid CSRF token.
func (h *AuthorizationHandler) HandleAuthorize(c *gin.Context) {
	action := c.PostForm("action") // "approve" or "deny"
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	scope := c.PostForm("scope")
	state := c.PostForm("state")
	nonce := c.PostForm("nonce")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")

	if !h.validateStateAndNonce(c, redirectURI, state, nonce) {
		return
	}

	// Deny path: redirect immediately with access_denied
	if action != "approve" {
		h.redirectWithError(
			c,
			redirectURI,
			state,
			errAccessDenied,
			"User denied the authorization request",
		)
		return
	}

	// Re-validate request on POST to prevent parameter tampering
	req, err := h.authorizationService.ValidateAuthorizationRequest(
		clientID, redirectURI, "code", scope, codeChallenge, codeChallengeMethod, nonce,
	)
	if err != nil {
		h.redirectWithError(c, redirectURI, state, oauthErrorCode(err), err.Error())
		return
	}

	userIDStr := getUserIDFromContext(c)

	// Persist the consent record
	if _, err := h.authorizationService.SaveUserAuthorization(
		c.Request.Context(),
		userIDStr,
		req.Client.ID,
		req.Client.ClientID,
		req.Scopes,
	); err != nil {
		h.redirectWithError(c, redirectURI, state, errServerError, "Failed to save authorization")
		return
	}

	h.issueCodeAndRedirect(c, req, userIDStr, state)
}

// issueCodeAndRedirect generates an authorization code and redirects to the client's redirect_uri.
func (h *AuthorizationHandler) issueCodeAndRedirect(
	c *gin.Context,
	req *services.AuthorizationRequest,
	userID, state string,
) {
	plainCode, _, err := h.authorizationService.CreateAuthorizationCode(
		c.Request.Context(),
		services.CreateAuthorizationCodeParams{
			ApplicationID:       req.Client.ID,
			ClientID:            req.Client.ClientID,
			UserID:              userID,
			RedirectURI:         req.RedirectURI,
			Scopes:              req.Scopes,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			Nonce:               req.Nonce,
		},
	)
	if err != nil {
		h.redirectWithError(
			c,
			req.RedirectURI,
			state,
			errServerError,
			"Failed to generate authorization code",
		)
		return
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid redirect_uri"})
		return
	}
	q := u.Query()
	q.Set("code", plainCode)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// redirectWithError sends an OAuth error response as a redirect to the client's redirect_uri.
// If redirect_uri is missing or invalid, renders a plain error page instead.
func (h *AuthorizationHandler) redirectWithError(
	c *gin.Context,
	redirectURI, state, errorCode, description string,
) {
	u, err := url.Parse(redirectURI)
	if redirectURI == "" || err != nil {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error:   errorCode,
				Message: description,
			}),
		)
		return
	}
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// ============================================================
// Account – authorized applications management
// ============================================================

// ListAuthorizations renders the user's authorized applications page (GET /account/authorizations).
func (h *AuthorizationHandler) ListAuthorizations(c *gin.Context) {
	userIDStr := getUserIDFromContext(c)

	auths, err := h.authorizationService.ListUserAuthorizations(c.Request.Context(), userIDStr)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to retrieve authorizations")
		return
	}

	// Build display models
	displayAuths := make([]templates.AuthorizationDisplay, 0, len(auths))
	for _, a := range auths {
		displayAuths = append(displayAuths, templates.AuthorizationDisplay{
			UUID:       a.UUID,
			ClientID:   a.ClientID,
			ClientName: a.ClientName,
			Scopes:     a.Scopes,
			GrantedAt:  a.GrantedAt,
			IsActive:   a.IsActive,
		})
	}

	userModel := getUserFromContext(c)
	if userModel == nil {
		userModel, _ = h.userService.GetUserByID(userIDStr)
	}
	if userModel == nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to load user")
		return
	}

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AccountAuthorizations(templates.AuthorizationsPageProps{
			BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps:    buildNavbarProps(c, userModel, "authorizations"),
			Authorizations: displayAuths,
			Success:        authzSuccessMessages[c.Query("success")],
			Error:          authzErrorMessages[c.Query("error")],
		}),
	)
}

// RevokeAuthorization revokes a user's consent for one application (POST /account/authorizations/:uuid/revoke).
func (h *AuthorizationHandler) RevokeAuthorization(c *gin.Context) {
	authUUID := c.Param("uuid")
	userIDStr := getUserIDFromContext(c)

	if err := h.authorizationService.RevokeUserAuthorization(
		c.Request.Context(),
		authUUID,
		userIDStr,
	); err != nil {
		if errors.Is(err, services.ErrAuthorizationNotFound) {
			c.Redirect(http.StatusFound, "/account/authorizations?error=not_found")
			return
		}
		c.Redirect(http.StatusFound, "/account/authorizations?error=server_error")
		return
	}

	c.Redirect(http.StatusFound, "/account/authorizations?success=revoked")
}

// ============================================================
// Helpers
// ============================================================

const (
	maxStateLength = 1024
	maxNonceLength = 1024
)

// validateStateAndNonce checks that state and nonce parameters don't exceed maximum lengths.
// Returns true if validation passes, false if an error redirect was sent.
func (h *AuthorizationHandler) validateStateAndNonce(
	c *gin.Context,
	redirectURI, state, nonce string,
) bool {
	if len(state) > maxStateLength {
		h.redirectWithError(
			c,
			redirectURI,
			"",
			errInvalidRequest,
			"state parameter exceeds maximum length",
		)
		return false
	}
	if len(nonce) > maxNonceLength {
		h.redirectWithError(
			c,
			redirectURI,
			state,
			errInvalidRequest,
			"nonce parameter exceeds maximum length",
		)
		return false
	}
	return true
}

// oauthErrorCode maps service errors to RFC 6749 error codes.
func oauthErrorCode(err error) string {
	switch {
	case errors.Is(err, services.ErrUnauthorizedClient):
		return errUnauthorizedClient
	case errors.Is(err, services.ErrUnsupportedResponseType):
		return "unsupported_response_type"
	case errors.Is(err, services.ErrInvalidAuthCodeScope):
		return errInvalidScope
	default:
		return errInvalidRequest
	}
}
