package handlers

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-gonic/gin"
)

const (
	// Grant type URNs (RFC 6749, RFC 8628)
	GrantTypeDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTypeDeviceCodeShort   = "device_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"

	// OAuth 2.0 error codes (RFC 6749 §5.2, RFC 8628 §3.5, RFC 8707 §2)
	errInvalidGrant         = "invalid_grant"
	errInvalidRequest       = "invalid_request"
	errInvalidClient        = "invalid_client"
	errInvalidScope         = "invalid_scope"
	errUnsupportedGrant     = "unsupported_grant_type"
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errExpiredToken         = "expired_token"
	errAccessDenied         = "access_denied"
	errServerError          = "server_error"
	errMissingToken         = "missing_token"
	errInvalidToken         = "invalid_token"
	errUnauthorizedClient   = "unauthorized_client"
	errInvalidTarget        = "invalid_target"
)

type TokenHandler struct {
	tokenService         *services.TokenService
	authorizationService *services.AuthorizationService
	config               *config.Config
	extraClaimsParser    *services.ExtraClaimsParser
}

func NewTokenHandler(
	ts *services.TokenService,
	as *services.AuthorizationService,
	cfg *config.Config,
) *TokenHandler {
	return &TokenHandler{
		tokenService:         ts,
		authorizationService: as,
		config:               cfg,
		extraClaimsParser:    services.NewExtraClaimsParser(cfg),
	}
}

// parseExtraClaims reads the optional extra_claims form parameter and writes
// an invalid_request response on failure. On success returns (claims, true);
// on failure the response is already written and callers must return.
func (h *TokenHandler) parseExtraClaims(c *gin.Context) (map[string]any, bool) {
	claims, err := h.extraClaimsParser.Parse(c.PostForm("extra_claims"))
	if err != nil {
		respondOAuthError(c, http.StatusBadRequest, errInvalidRequest, err.Error())
		return nil, false
	}
	return claims, true
}

// parseResourceParam reads the optional repeatable `resource` form parameter
// (RFC 8707) and writes an invalid_target response on failure. On success
// returns (resources, true); on failure the response is already written and
// callers must return.
func (h *TokenHandler) parseResourceParam(c *gin.Context) ([]string, bool) {
	values, err := util.ValidateResourceIndicators(c.PostFormArray("resource"))
	if err != nil {
		respondOAuthError(c, http.StatusBadRequest, errInvalidTarget, err.Error())
		return nil, false
	}
	return values, true
}

// normalizeAudience collapses an audience value list into the JWT-shaped
// `any` used in both /oauth/tokeninfo and /oauth/introspect responses:
// nil for empty, a plain string for single-value, or []string for
// multi-value (matching JWT `aud` conventions).
func normalizeAudience(values []string) any {
	switch len(values) {
	case 0:
		return nil
	case 1:
		return values[0]
	default:
		out := make([]string, len(values))
		copy(out, values)
		return out
	}
}

// introspectAudience returns the value to emit as the `aud` field on an
// RFC 7662 introspection response, or nil to omit the claim.
//
// Refresh tokens always return nil. The introspection response's `token_type`
// field is hard-coded to "Bearer" (matching how access tokens are presented),
// so a resource server that authenticates with `active=true` AND
// `aud == its-own-id` cannot tell a refresh token apart from an access
// token. Advertising any `aud` on a refresh token would let it be mistakenly
// accepted as an access token whenever the configured `JWT_AUDIENCE` happens
// to match a resource-server identifier.
//
// For access tokens, `tok.Resource` is the audience snapshot taken at
// issuance — it is exactly what the JWT was signed with (per-request RFC
// 8707 binding when supplied, or the static JWTAudience config that the
// JWT provider fell back to). Reading the snapshot rather than re-deriving
// from the live config means rotating `JWT_AUDIENCE` while older tokens are
// active does NOT change what introspection reports — preventing resource
// servers that trust introspection from accepting tokens that were never
// minted for them.
func introspectAudience(tok *models.AccessToken) any {
	if !tok.IsAccessToken() {
		return nil
	}
	return normalizeAudience([]string(tok.Resource))
}

// audienceFromClaims extracts the JWT `aud` claim from a decoded MapClaims
// map and normalizes it to []string. The jwt library decodes single-string
// aud claims as `string` and multi-value aud claims as `[]any` (via
// json.Unmarshal); this helper folds both shapes into the same slice form
// for `normalizeAudience`. Used by /oauth/tokeninfo, which validates the JWT
// directly (no extra DB lookup) and therefore reads the aud snapshot from
// the signed token rather than the persisted Resource column. Both sources
// are taken at issuance and must agree.
func audienceFromClaims(claims map[string]any) []string {
	raw, ok := claims["aud"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// buildTokenResponse constructs a standard OAuth 2.0 token response (RFC 6749 §5.1).
func buildTokenResponse(accessToken, refreshToken *models.AccessToken, idToken string) gin.H {
	expiresIn := max(int(time.Until(accessToken.ExpiresAt).Seconds()), 0)
	resp := gin.H{
		"access_token": accessToken.RawToken,
		"token_type":   accessToken.TokenType,
		"expires_in":   expiresIn,
		"scope":        accessToken.Scopes,
	}
	if refreshToken != nil {
		resp["refresh_token"] = refreshToken.RawToken
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	return resp
}

// Token godoc
//
//	@Summary		Request access token
//	@Description	Exchange a device code, authorization code, refresh token, or client credentials for an access token (RFC 6749 / RFC 8628). Accepts the optional repeatable `resource` parameter (RFC 8707) on every grant type.
//	@Tags			OAuth
//	@Accept			json
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			grant_type		formData	string																							true	"Grant type: 'urn:ietf:params:oauth:grant-type:device_code', 'authorization_code', 'refresh_token', or 'client_credentials'"
//	@Param			device_code		formData	string																							false	"Device code (required when grant_type=device_code)"
//	@Param			client_id		formData	string																							false	"OAuth client ID (required for non-Basic-Auth flows)"
//	@Param			client_secret	formData	string																							false	"OAuth client secret (confidential clients only; alternative to HTTP Basic Auth)"
//	@Param			refresh_token	formData	string																							false	"Refresh token (required when grant_type=refresh_token)"
//	@Param			code			formData	string																							false	"Authorization code (required when grant_type=authorization_code)"
//	@Param			redirect_uri	formData	string																							false	"Redirect URI (required when grant_type=authorization_code)"
//	@Param			code_verifier	formData	string																							false	"PKCE code verifier (RFC 7636; required for public clients on grant_type=authorization_code)"
//	@Param			scope			formData	string																							false	"Space-separated scopes; refresh_token / client_credentials may narrow the original grant"
//	@Param			resource		formData	[]string																						false	"RFC 8707 Resource Indicator(s) — bound to the issued access token's `aud` claim. Repeat to send multiple. Each value must be an absolute http(s) URL with a non-empty host and no fragment."	collectionFormat(multi)
//	@Param			extra_claims	formData	string																							false	"Optional caller-supplied JWT claims as a JSON object (subject to size guards and reserved-key rejection)"
//	@Success		200				{object}	object{access_token=string,refresh_token=string,token_type=string,expires_in=int,scope=string}	"Access token issued successfully"
//	@Failure		400				{object}	object{error=string,error_description=string}													"Invalid request (unsupported_grant_type, invalid_request, authorization_pending, slow_down, expired_token, access_denied, invalid_grant, invalid_scope, invalid_target)"
//	@Failure		401				{object}	object{error=string,error_description=string}													"Client authentication failed (invalid_client)"
//	@Failure		429				{object}	object{error=string,error_description=string}													"Rate limit exceeded"
//	@Failure		500				{object}	object{error=string,error_description=string}													"Internal server error"
//	@Router			/oauth/token [post]
func (h *TokenHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case GrantTypeDeviceCode:
		h.handleDeviceCodeGrant(c)
	case GrantTypeRefreshToken:
		h.handleRefreshTokenGrant(c)
	case GrantTypeAuthorizationCode:
		h.handleAuthorizationCodeGrant(c)
	case GrantTypeClientCredentials:
		h.handleClientCredentialsGrant(c)
	default:
		respondOAuthError(
			c,
			http.StatusBadRequest,
			errUnsupportedGrant,
			"Supported grant types: device_code, refresh_token, authorization_code, client_credentials",
		)
	}
}

// handleDeviceCodeGrant handles device code grant type (RFC 8628)
func (h *TokenHandler) handleDeviceCodeGrant(c *gin.Context) {
	deviceCode := c.PostForm("device_code")
	clientID := c.PostForm("client_id")

	if deviceCode == "" || clientID == "" {
		respondOAuthError(
			c,
			http.StatusBadRequest,
			errInvalidRequest,
			"device_code and client_id are required",
		)
		return
	}

	extraClaims, ok := h.parseExtraClaims(c)
	if !ok {
		return
	}

	resource, ok := h.parseResourceParam(c)
	if !ok {
		return
	}

	accessToken, refreshToken, err := h.tokenService.ExchangeDeviceCode(
		c.Request.Context(),
		deviceCode,
		clientID,
		extraClaims,
		resource,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrAuthorizationPending):
			respondOAuthError(c, http.StatusBadRequest, errAuthorizationPending, "")
		case errors.Is(err, services.ErrSlowDown):
			respondOAuthError(c, http.StatusBadRequest, errSlowDown, "")
		case errors.Is(err, services.ErrExpiredToken):
			respondOAuthError(c, http.StatusBadRequest, errExpiredToken, "")
		case errors.Is(err, services.ErrAccessDenied):
			respondOAuthError(c, http.StatusBadRequest, errAccessDenied, "")
		case errors.Is(err, services.ErrInvalidTarget):
			respondOAuthError(
				c,
				http.StatusBadRequest,
				errInvalidTarget,
				"Requested resource exceeds the audience granted at /oauth/device/code",
			)
		default:
			log.Printf("[token] device code exchange error: %v", err)
			respondOAuthError(
				c,
				http.StatusInternalServerError,
				errServerError,
				"An internal error occurred",
			)
		}
		return
	}

	c.JSON(http.StatusOK, buildTokenResponse(accessToken, refreshToken, ""))
}

// handleRefreshTokenGrant handles refresh token grant type (RFC 6749)
func (h *TokenHandler) handleRefreshTokenGrant(c *gin.Context) {
	// 1. Parse parameters
	refreshTokenString := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	requestedScopes := c.PostForm("scope") // Optional

	// 2. Validate required parameters
	if refreshTokenString == "" || clientID == "" {
		respondOAuthError(
			c,
			http.StatusBadRequest,
			errInvalidRequest,
			"refresh_token and client_id are required",
		)
		return
	}

	extraClaims, ok := h.parseExtraClaims(c)
	if !ok {
		return
	}

	resource, ok := h.parseResourceParam(c)
	if !ok {
		return
	}

	// 3. Call service to refresh token
	newAccessToken, newRefreshToken, err := h.tokenService.RefreshAccessToken(
		c.Request.Context(),
		refreshTokenString,
		clientID,
		requestedScopes,
		extraClaims,
		resource,
	)
	// 4. Error handling (RFC 6749 / RFC 8707 error codes)
	if err != nil {
		switch {
		case errors.Is(err, token.ErrInvalidRefreshToken),
			errors.Is(err, token.ErrExpiredRefreshToken):
			respondOAuthError(
				c,
				http.StatusBadRequest,
				errInvalidGrant,
				"Refresh token is invalid or expired",
			)
		case errors.Is(err, services.ErrAccessDenied):
			// Per RFC 6749 §5.2, invalid_client should use 401 and include WWW-Authenticate
			c.Header("WWW-Authenticate", `Basic realm="token"`)
			respondOAuthError(
				c,
				http.StatusUnauthorized,
				errInvalidClient,
				"Client authentication failed",
			)
		case errors.Is(err, token.ErrInvalidScope):
			respondOAuthError(
				c,
				http.StatusBadRequest,
				errInvalidScope,
				"Requested scope exceeds original grant",
			)
		case errors.Is(err, services.ErrInvalidTarget):
			respondOAuthError(
				c,
				http.StatusBadRequest,
				errInvalidTarget,
				"Requested resource exceeds original grant",
			)
		default:
			respondOAuthError(
				c,
				http.StatusInternalServerError,
				errServerError,
				"Token refresh failed",
			)
		}
		return
	}

	// 5. Return new tokens (RFC 6749 format)
	c.JSON(http.StatusOK, buildTokenResponse(newAccessToken, newRefreshToken, ""))
}

// TokenInfo godoc
//
//	@Summary		Validate access token
//	@Description	Verify JWT token validity and retrieve token information (RFC 7662 style introspection)
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			Authorization	header		string																				true	"Bearer token (format: 'Bearer <token>')"
//	@Success		200				{object}	object{active=bool,user_id=string,client_id=string,scope=string,exp=int,iss=string,subject_type=string,aud=object}	"Token is valid. `aud` mirrors the JWT's signed audience snapshot (per-request RFC 8707 resource, otherwise the static JWT_AUDIENCE the JWT was minted with); collapsed to a string for a single value, slice for multiple, omitted when the JWT carries no audience."
//	@Failure		401				{object}	object{error=string,error_description=string}										"Token is invalid or expired (missing_token, invalid_token)"
//	@Router			/oauth/tokeninfo [get]
func (h *TokenHandler) TokenInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		respondOAuthError(c, http.StatusUnauthorized, errMissingToken, "")
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	result, err := h.tokenService.ValidateToken(c.Request.Context(), tokenString)
	if err != nil {
		log.Printf("[token] token validation error: %v", err)
		respondOAuthError(
			c,
			http.StatusUnauthorized,
			errInvalidToken,
			"Token is invalid or expired",
		)
		return
	}

	// Identify whether this is a user-delegated token or a machine (client credentials) token
	subjectType := "user"
	if services.IsMachineUserID(result.UserID) {
		subjectType = "client"
	}

	resp := gin.H{
		"active":       result.Valid,
		"user_id":      result.UserID,
		"client_id":    result.ClientID,
		"scope":        result.Scopes,
		"exp":          result.ExpiresAt.Unix(),
		"iss":          h.config.BaseURL,
		"subject_type": subjectType,
	}

	// Emit the JWT's signed `aud` claim so callers using /oauth/tokeninfo see
	// the same per-token audience that /oauth/introspect reports. Both sources
	// are issuance-time snapshots: introspect reads the persisted Resource
	// column, tokeninfo reads the verified JWT claim — they must agree because
	// both are written at the same instant. Validation already rejects refresh
	// tokens (only access tokens reach this point), so this never advertises
	// a refresh-token aud the way it would on /oauth/introspect.
	if aud := normalizeAudience(audienceFromClaims(result.Claims)); aud != nil {
		resp["aud"] = aud
	}

	c.JSON(http.StatusOK, resp)
}

// Introspect godoc
//
//	@Summary		Introspect token (RFC 7662)
//	@Description	Determine the active state and metadata of an OAuth 2.0 token. Requires client authentication via HTTP Basic Auth or form-body client credentials.
//	@Tags			OAuth
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			token			formData	string																																		true	"The token to introspect"
//	@Param			token_type_hint	formData	string																																		false	"Hint about the type of token: 'access_token' or 'refresh_token'"
//	@Param			client_id		formData	string																																		false	"Client ID (alternative to HTTP Basic Auth)"
//	@Param			client_secret	formData	string																																		false	"Client secret (alternative to HTTP Basic Auth)"
//	@Success		200				{object}	object{active=bool,scope=string,client_id=string,username=string,token_type=string,exp=int,iat=int,sub=string,iss=string,jti=string,aud=object}	"Token introspection response. `aud` is included only for active access tokens — it is the persisted RFC 8707 resource set when present, otherwise the configured JWT_AUDIENCE; collapsed to a string for a single value, slice for multiple. Refresh tokens always omit `aud` to avoid being mistaken for access tokens."
//	@Failure		401				{object}	object{error=string,error_description=string}																																																																																																																																																																																																																																																																																																																																																																																																"Client authentication failed"
//	@Router			/oauth/introspect [post]
func (h *TokenHandler) Introspect(c *gin.Context) {
	// 1. Authenticate the calling client (RFC 7662 §2.1)
	clientID, clientSecret := parseClientCredentials(c)
	if clientID == "" || clientSecret == "" {
		c.Header("WWW-Authenticate", `Basic realm="authgate"`)
		respondOAuthError(
			c,
			http.StatusUnauthorized,
			errInvalidClient,
			"Client authentication required",
		)
		return
	}

	// Verify client credentials
	if err := h.tokenService.AuthenticateClient(
		c.Request.Context(),
		clientID,
		clientSecret,
	); err != nil {
		c.Header("WWW-Authenticate", `Basic realm="authgate"`)
		respondOAuthError(
			c,
			http.StatusUnauthorized,
			errInvalidClient,
			"Client authentication failed",
		)
		return
	}

	// 2. Get the token parameter (RFC 7662 §2.1: REQUIRED)
	tokenString := c.PostForm("token")
	if tokenString == "" {
		respondOAuthError(
			c,
			http.StatusBadRequest,
			errInvalidRequest,
			"token parameter is required",
		)
		return
	}

	// 3. Introspect the token
	// RFC 7662 §2.2: If the token is not active, return {"active": false}
	tok, active := h.tokenService.IntrospectToken(c.Request.Context(), tokenString, clientID)
	if !active || tok == nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	// 4. Build RFC 7662 §2.2 response
	resp := gin.H{
		"active":     true,
		"scope":      tok.Scopes,
		"client_id":  tok.ClientID,
		"token_type": tok.TokenType,
		"exp":        tok.ExpiresAt.Unix(),
		"iat":        tok.CreatedAt.Unix(),
		"sub":        tok.UserID,
		"iss":        h.config.BaseURL,
		"jti":        tok.ID,
	}

	// Audience: for access tokens, report the audience snapshot taken at
	// issuance (per-request RFC 8707 resource OR static JWTAudience config
	// — whichever was actually written into the JWT). Refresh tokens always
	// omit `aud` because the introspection response's `token_type` is
	// hard-coded "Bearer" and a resource server checking `active && aud=mine`
	// could otherwise be tricked into accepting a refresh token as an access
	// token. See introspectAudience for the full rationale.
	if aud := introspectAudience(tok); aud != nil {
		resp["aud"] = aud
	}

	// Add username for user-delegated tokens (not M2M / client credentials tokens)
	if !services.IsMachineUserID(tok.UserID) {
		if user, err := h.tokenService.GetUserByID(tok.UserID); err == nil {
			resp["username"] = user.Username
		}
	}

	c.JSON(http.StatusOK, resp)
}

// Revoke godoc
//
//	@Summary		Revoke token
//	@Description	Revoke an access token or refresh token (RFC 7009). Returns 200 for both successful revocation and invalid tokens to prevent token scanning attacks.
//	@Tags			OAuth
//	@Accept			json
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			token			formData	string											true	"Token to revoke (access token or refresh token)"
//	@Param			token_type_hint	formData	string											false	"Token type hint: 'access_token' or 'refresh_token'"
//	@Success		200				{string}	string											"Token revoked successfully (or invalid token)"
//	@Failure		400				{object}	object{error=string,error_description=string}	"Invalid request (token parameter missing)"
//	@Router			/oauth/revoke [post]
func (h *TokenHandler) Revoke(c *gin.Context) {
	// Get token from request
	// RFC 7009 specifies that the token parameter is REQUIRED
	token := c.PostForm("token")
	if token == "" {
		respondOAuthError(
			c,
			http.StatusBadRequest,
			errInvalidRequest,
			"token parameter is required",
		)
		return
	}

	// Optional: token_type_hint can be "access_token" or "refresh_token"
	// Since we only support access tokens, we can ignore this parameter
	// tokenTypeHint := c.PostForm("token_type_hint")

	// Revoke the token
	err := h.tokenService.RevokeToken(token)
	if err != nil {
		// RFC 7009 section 2.2: The authorization server responds with HTTP status code 200
		// if the token has been revoked successfully or if the client submitted an invalid token.
		// This is to prevent token scanning attacks.
		c.Status(http.StatusOK)
		return
	}

	// Success response (RFC 7009)
	c.Status(http.StatusOK)
}

// handleClientCredentialsGrant handles the client_credentials grant type (RFC 6749 §4.4).
// Client authentication is accepted via HTTP Basic Auth (preferred per RFC 6749 §2.3.1)
// or as client_id / client_secret form-body parameters.
// Only confidential clients with the client_credentials flow enabled may use this endpoint.
// No refresh token is issued in the response.
func (h *TokenHandler) handleClientCredentialsGrant(c *gin.Context) {
	clientID, clientSecret := parseClientCredentials(c)
	if clientID == "" || clientSecret == "" {
		c.Header("WWW-Authenticate", `Basic realm="authgate"`)
		respondOAuthError(
			c,
			http.StatusUnauthorized,
			errInvalidClient,
			"Client authentication required: use HTTP Basic Auth or provide client_id and client_secret in the request body",
		)
		return
	}

	requestedScopes := c.PostForm("scope") // Optional

	extraClaims, ok := h.parseExtraClaims(c)
	if !ok {
		return
	}

	resource, ok := h.parseResourceParam(c)
	if !ok {
		return
	}

	accessToken, err := h.tokenService.IssueClientCredentialsToken(
		c.Request.Context(),
		clientID,
		clientSecret,
		requestedScopes,
		extraClaims,
		resource,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidClientCredentials),
			errors.Is(err, services.ErrClientNotConfidential):
			// RFC 6749 §5.2: use 401 + WWW-Authenticate for invalid_client
			c.Header("WWW-Authenticate", `Basic realm="authgate"`)
			respondOAuthError(
				c,
				http.StatusUnauthorized,
				errInvalidClient,
				"Client authentication failed",
			)
		case errors.Is(err, services.ErrClientCredentialsFlowDisabled):
			respondOAuthError(c, http.StatusBadRequest, errUnauthorizedClient,
				"Client credentials flow is not enabled for this client")
		case errors.Is(err, services.ErrInvalidTarget):
			respondOAuthError(
				c,
				http.StatusBadRequest,
				errInvalidTarget,
				"Requested resource is not allowed for this client",
			)
		case errors.Is(err, token.ErrInvalidScope):
			respondOAuthError(
				c,
				http.StatusBadRequest,
				errInvalidScope,
				"Requested scope exceeds client permissions or contains restricted scopes (openid, offline_access are not permitted)",
			)
		default:
			respondOAuthError(
				c,
				http.StatusInternalServerError,
				errServerError,
				"Token issuance failed",
			)
		}
		return
	}

	// RFC 6749 §4.4.3: response MUST NOT include a refresh_token
	c.JSON(http.StatusOK, buildTokenResponse(accessToken, nil, ""))
}

// handleAuthorizationCodeGrant handles the authorization_code grant type (RFC 6749 §4.1.3).
func (h *TokenHandler) handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret") // Empty for public clients
	codeVerifier := c.PostForm("code_verifier") // PKCE; empty for confidential clients

	if code == "" || redirectURI == "" || clientID == "" {
		respondOAuthError(
			c,
			http.StatusBadRequest,
			errInvalidRequest,
			"code, redirect_uri, and client_id are required",
		)
		return
	}

	extraClaims, ok := h.parseExtraClaims(c)
	if !ok {
		return
	}

	resource, ok := h.parseResourceParam(c)
	if !ok {
		return
	}

	// Validate and consume the authorization code. ExchangeCode now performs
	// the RFC 8707 §2.2 subset check BEFORE marking the code as used so a
	// rejected resource doesn't burn the single-use code.
	authCode, err := h.authorizationService.ExchangeCode(
		c.Request.Context(),
		code, clientID, redirectURI, clientSecret, codeVerifier, resource,
	)
	if err != nil {
		errCode := errInvalidGrant
		var description string
		switch {
		case errors.Is(err, services.ErrUnauthorizedClient):
			errCode = errUnauthorizedClient
			description = "Client authentication failed"
		case errors.Is(err, services.ErrAuthCodeNotFound):
			description = "Authorization code is invalid or expired"
		case errors.Is(err, services.ErrAuthCodeExpired):
			description = "Authorization code has expired"
		case errors.Is(err, services.ErrAuthCodeAlreadyUsed):
			description = "Authorization code has already been used"
		case errors.Is(err, services.ErrInvalidRedirectURI):
			description = "Redirect URI does not match"
		case errors.Is(err, services.ErrPKCERequired):
			description = "PKCE code_verifier is required for public clients"
		case errors.Is(err, services.ErrInvalidCodeVerifier):
			description = "PKCE code_verifier validation failed"
		case errors.Is(err, services.ErrInvalidTarget):
			errCode = errInvalidTarget
			description = "Requested resource exceeds the audience granted at /authorize"
		default:
			log.Printf("[token] authorization code exchange error: %v", err)
			description = "An internal error occurred"
		}
		respondOAuthError(c, http.StatusBadRequest, errCode, description)
		return
	}

	// Resolve the UserAuthorization ID so tokens can be cascade-revoked later
	var authorizationID *uint
	if ua, _ := h.authorizationService.GetUserAuthorization(
		authCode.UserID, authCode.ApplicationID,
	); ua != nil {
		id := ua.ID
		authorizationID = &id
	}

	// Issue access + refresh tokens (+ ID token when openid scope was granted).
	// The service uses `resource` (token-time, possibly narrowed) for the
	// access token's audience and falls back to authCode.Resource for the
	// refresh token, so future refreshes can re-narrow against the original
	// /authorize-time grant rather than the narrowed access-token audience.
	accessToken, refreshToken, idToken, err := h.tokenService.ExchangeAuthorizationCode(
		c.Request.Context(),
		authCode,
		authorizationID,
		extraClaims,
		resource,
	)
	if err != nil {
		respondOAuthError(
			c,
			http.StatusInternalServerError,
			errServerError,
			"Failed to issue tokens",
		)
		return
	}

	var rt *models.AccessToken
	if refreshToken != nil && h.config.EnableRefreshTokens {
		rt = refreshToken
	}
	c.JSON(http.StatusOK, buildTokenResponse(accessToken, rt, idToken))
}
