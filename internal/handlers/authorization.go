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

	// Validate the authorization request parameters FIRST. This proves the
	// redirect_uri is registered to the client. Validating resource (which
	// can fail with a redirect to redirect_uri) before this would let an
	// attacker craft an invalid `resource` plus a non-registered
	// `redirect_uri` to coerce the server into an open redirect.
	req, err := h.authorizationService.ValidateAuthorizationRequest(
		c.Request.Context(),
		clientID, redirectURI, responseType, scope, codeChallenge, codeChallengeMethod, nonce,
	)
	if err != nil {
		h.handleAuthorizeError(c, redirectURI, state, err)
		return
	}

	// RFC 8707 Resource Indicators (repeatable parameter). Validated AFTER
	// the redirect_uri has been confirmed registered, so an invalid_target
	// redirect goes to a trusted destination.
	resource, err := util.ValidateResourceIndicators(c.QueryArray("resource"))
	if err != nil {
		h.redirectWithError(c, redirectURI, state, errInvalidTarget, err.Error())
		return
	}
	req.Resource = resource

	userIDStr := getUserIDFromContext(c)

	// Retrieve the logged-in user for display
	user, err := h.userService.GetUserByID(c.Request.Context(), userIDStr)
	if err != nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// If ConsentRemember is enabled and the user has already consented to
	// the same client+scopes+resource set, skip the consent page and issue
	// a code immediately. The resource set must match EXACTLY — neither a
	// no-resource request matching a resource-bound consent nor a
	// resource-bound request matching a no-resource consent qualifies, since
	// the user only ever approved a specific audience binding (or its
	// absence) and silently widening/narrowing it would shift trust they
	// never granted.
	if h.config.ConsentRemember {
		existing, _ := h.authorizationService.GetUserAuthorization(userIDStr, req.Client.ID)
		if existing != nil &&
			util.IsScopeSubset(existing.Scopes, req.Scopes) &&
			util.IsStringSliceSetEqual([]string(existing.Resource), req.Resource) {
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
		Resource:            req.Resource,
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

	// Re-validate request on POST to prevent parameter tampering. Must run
	// BEFORE resource validation so the redirect_uri is proven registered —
	// see GET handler for the open-redirect rationale.
	req, err := h.authorizationService.ValidateAuthorizationRequest(
		c.Request.Context(),
		clientID, redirectURI, "code", scope, codeChallenge, codeChallengeMethod, nonce,
	)
	if err != nil {
		h.handleAuthorizeError(c, redirectURI, state, err)
		return
	}

	// RFC 8707 Resource Indicators (repeatable form parameter). The GET handler
	// emits hidden <input name="resource"> per value so the POST round-trip
	// preserves the original request's audience binding.
	resource, err := util.ValidateResourceIndicators(c.PostFormArray("resource"))
	if err != nil {
		h.redirectWithError(c, redirectURI, state, errInvalidTarget, err.Error())
		return
	}
	req.Resource = resource

	userIDStr := getUserIDFromContext(c)

	// Persist the consent record (with the approved resource set, if any).
	// UserAuthorization is now resource-aware: the GET-side remembered-consent
	// shortcut requires an exact resource-set match before auto-approving, so
	// saving a resource-bound consent here cannot accidentally widen a later
	// no-resource request — it just makes the (client, scopes, resource)
	// triple a re-usable shortcut. Persisting also means the issued tokens
	// get an AuthorizationID FK so the user can revoke them from
	// /account/authorizations and so admin-initiated client revocations
	// cascade to them.
	if _, err := h.authorizationService.SaveUserAuthorization(
		c.Request.Context(),
		userIDStr,
		req.Client.ID,
		req.Client.ClientID,
		req.Scopes,
		req.Resource,
	); err != nil {
		h.redirectWithError(
			c,
			redirectURI,
			state,
			errServerError,
			"Failed to save authorization",
		)
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
			Resource:            req.Resource,
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

// handleAuthorizeError converts a ValidateAuthorizationRequest error into the
// right response. Per RFC 6749 §3.1.2.4, when redirect_uri has not yet been
// proven registered for the client, the AS MUST NOT redirect — otherwise the
// caller-supplied redirect_uri becomes an open redirect.
//
// ValidateAuthorizationRequest checks parameters in this order:
//
//	response_type → client lookup → client active → auth-code flow enabled →
//	redirect_uri → scope → PKCE
//
// Anything that can fail BEFORE the redirect_uri match (response_type,
// client lookup/active/flow-disabled, redirect_uri itself) must render an
// error page locally; only failures after that point may safely redirect
// the OAuth error to the now-validated redirect_uri.
func (h *AuthorizationHandler) handleAuthorizeError(
	c *gin.Context,
	redirectURI, state string,
	err error,
) {
	if errors.Is(err, services.ErrInvalidRedirectURI) ||
		errors.Is(err, services.ErrUnauthorizedClient) ||
		errors.Is(err, services.ErrUnsupportedResponseType) {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error:   oauthErrorCode(err),
				Message: err.Error(),
			}),
		)
		return
	}
	h.redirectWithError(c, redirectURI, state, oauthErrorCode(err), err.Error())
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

	displayAuths := toAuthorizationDisplaySlice(auths)

	userModel := getUserFromContext(c)
	if userModel == nil {
		userModel, _ = h.userService.GetUserByID(c.Request.Context(), userIDStr)
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

// validateStateAndNonce checks that state and nonce parameters don't exceed
// maximum lengths. Returns true if validation passes, false if an error
// response was written.
//
// This runs BEFORE ValidateAuthorizationRequest, so the redirect_uri has not
// yet been proven registered for the client. Reflecting the OAuth error to
// the caller-supplied redirect_uri here would be an open redirect — an
// attacker could pair an oversized state/nonce with an attacker-controlled
// redirect_uri to coerce the AS into redirecting off-site. We render the
// error page locally instead. Per RFC 6749 §3.1.2.4 the AS MUST NOT redirect
// to an unverified redirect_uri.
func (h *AuthorizationHandler) validateStateAndNonce(
	c *gin.Context,
	_, state, nonce string,
) bool {
	if len(state) > maxStateLength {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error:   errInvalidRequest,
				Message: "state parameter exceeds maximum length",
			}),
		)
		return false
	}
	if len(nonce) > maxNonceLength {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.ErrorPage(templates.ErrorPageProps{
				Error:   errInvalidRequest,
				Message: "nonce parameter exceeds maximum length",
			}),
		)
		return false
	}
	return true
}

// oauthErrorCode maps service errors to RFC 6749 / RFC 8707 error codes.
func oauthErrorCode(err error) string {
	switch {
	case errors.Is(err, services.ErrUnauthorizedClient):
		return errUnauthorizedClient
	case errors.Is(err, services.ErrUnsupportedResponseType):
		return "unsupported_response_type"
	case errors.Is(err, services.ErrInvalidAuthCodeScope):
		return errInvalidScope
	case errors.Is(err, services.ErrInvalidTarget):
		return errInvalidTarget
	default:
		return errInvalidRequest
	}
}
