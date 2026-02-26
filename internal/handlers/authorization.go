package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

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

	if len(state) > maxStateLength {
		h.redirectWithError(
			c,
			redirectURI,
			"",
			errInvalidRequest,
			"state parameter exceeds maximum length",
		)
		return
	}

	if len(nonce) > maxNonceLength {
		h.redirectWithError(
			c,
			redirectURI,
			state,
			errInvalidRequest,
			"nonce parameter exceeds maximum length",
		)
		return
	}

	// Validate the authorization request parameters
	req, err := h.authorizationService.ValidateAuthorizationRequest(
		clientID, redirectURI, responseType, scope, codeChallengeMethod, nonce,
	)
	if err != nil {
		h.redirectWithError(c, redirectURI, state, oauthErrorCode(err), err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr := userID.(string)

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
		if existing != nil && scopesAreCovered(existing.Scopes, req.Scopes) {
			h.issueCodeAndRedirect(
				c,
				req,
				userIDStr,
				redirectURI,
				state,
				nonce,
				codeChallenge,
				codeChallengeMethod,
			)
			return
		}
	}

	// Render the consent page
	templates.RenderTempl(c, http.StatusOK, templates.AuthorizePage(templates.AuthorizePageProps{
		BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: templates.NavbarProps{
			Username:   user.Username,
			IsAdmin:    user.IsAdmin(),
			ActiveLink: "",
		},
		Username:            user.Username,
		ClientID:            req.Client.ClientID,
		ClientName:          req.Client.ClientName,
		ClientDescription:   req.Client.Description,
		RedirectURI:         redirectURI,
		Scopes:              req.Scopes,
		ScopeList:           strings.Fields(req.Scopes),
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
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

	if len(state) > maxStateLength {
		h.redirectWithError(
			c,
			redirectURI,
			"",
			errInvalidRequest,
			"state parameter exceeds maximum length",
		)
		return
	}

	if len(nonce) > maxNonceLength {
		h.redirectWithError(
			c,
			redirectURI,
			state,
			errInvalidRequest,
			"nonce parameter exceeds maximum length",
		)
		return
	}

	// Deny path: redirect immediately with access_denied
	if action != "approve" {
		h.redirectWithError(
			c,
			redirectURI,
			state,
			"access_denied",
			"User denied the authorization request",
		)
		return
	}

	// Re-validate request on POST to prevent parameter tampering
	req, err := h.authorizationService.ValidateAuthorizationRequest(
		clientID, redirectURI, "code", scope, codeChallengeMethod, nonce,
	)
	if err != nil {
		h.redirectWithError(c, redirectURI, state, oauthErrorCode(err), err.Error())
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr := userID.(string)

	// Persist the consent record
	if _, err := h.authorizationService.SaveUserAuthorization(
		c.Request.Context(),
		userIDStr,
		req.Client.ID,
		req.Client.ClientID,
		req.Scopes,
	); err != nil {
		h.redirectWithError(c, redirectURI, state, "server_error", "Failed to save authorization")
		return
	}

	h.issueCodeAndRedirect(
		c, req, userIDStr, redirectURI, state, nonce, codeChallenge, codeChallengeMethod,
	)
}

// issueCodeAndRedirect generates an authorization code and redirects to the client's redirect_uri.
func (h *AuthorizationHandler) issueCodeAndRedirect(
	c *gin.Context,
	req *services.AuthorizationRequest,
	userID, redirectURI, state, nonce, codeChallenge, codeChallengeMethod string,
) {
	plainCode, _, err := h.authorizationService.CreateAuthorizationCode(
		c.Request.Context(),
		req.Client.ID,
		req.Client.ClientID,
		userID,
		redirectURI,
		req.Scopes,
		codeChallenge,
		codeChallengeMethod,
		nonce,
	)
	if err != nil {
		h.redirectWithError(
			c,
			redirectURI,
			state,
			"server_error",
			"Failed to generate authorization code",
		)
		return
	}

	u, err := url.Parse(redirectURI)
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
	if redirectURI == "" {
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
	u, err := url.Parse(redirectURI)
	if err != nil {
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
	userID, _ := c.Get("user_id")
	user, _ := c.Get("user")
	userIDStr := userID.(string)

	auths, err := h.authorizationService.ListUserAuthorizations(c.Request.Context(), userIDStr)
	if err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Failed to retrieve authorizations",
			}),
		)
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

	isAdmin := false
	username := ""
	if um, ok := user.(*models.User); ok {
		isAdmin = um.IsAdmin()
		username = um.Username
	} else if u, err := h.userService.GetUserByID(userIDStr); err == nil {
		isAdmin = u.IsAdmin()
		username = u.Username
	}

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AccountAuthorizations(templates.AuthorizationsPageProps{
			BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: templates.NavbarProps{
				Username:   username,
				IsAdmin:    isAdmin,
				ActiveLink: "authorizations",
			},
			Authorizations: displayAuths,
			Success:        c.Query("success"),
			Error:          c.Query("error"),
		}),
	)
}

// RevokeAuthorization revokes a user's consent for one application (POST /account/authorizations/:uuid/revoke).
func (h *AuthorizationHandler) RevokeAuthorization(c *gin.Context) {
	authUUID := c.Param("uuid")
	userID, _ := c.Get("user_id")
	userIDStr := userID.(string)

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
	errInvalidRequest = "invalid_request"
	maxStateLength    = 1024
	maxNonceLength    = 1024
)

// oauthErrorCode maps service errors to RFC 6749 error codes.
func oauthErrorCode(err error) string {
	switch {
	case errors.Is(err, services.ErrUnauthorizedClient):
		return "unauthorized_client"
	case errors.Is(err, services.ErrUnsupportedResponseType):
		return "unsupported_response_type"
	case errors.Is(err, services.ErrInvalidAuthCodeScope):
		return "invalid_scope"
	default:
		return errInvalidRequest
	}
}

// scopesAreCovered returns true when all scopes in requested are present in granted.
func scopesAreCovered(grantedScopes, requestedScopes string) bool {
	granted := make(map[string]bool)
	for s := range strings.FieldsSeq(grantedScopes) {
		granted[s] = true
	}
	for s := range strings.FieldsSeq(requestedScopes) {
		if !granted[s] {
			return false
		}
	}
	return true
}
