package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/token"

	"github.com/gin-gonic/gin"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	// https://datatracker.ietf.org/doc/html/rfc6749#section-6
	GrantTypeRefreshToken = "refresh_token"
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
	GrantTypeAuthorizationCode = "authorization_code"
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
	GrantTypeClientCredentials = "client_credentials"
	// errInvalidGrant is reused across authorization code grant error paths
	errInvalidGrant = "invalid_grant"
)

type TokenHandler struct {
	tokenService         *services.TokenService
	authorizationService *services.AuthorizationService
	config               *config.Config
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
	}
}

// Token godoc
//
//	@Summary		Request access token
//	@Description	Exchange device code or refresh token for access token (RFC 8628 and RFC 6749)
//	@Tags			OAuth
//	@Accept			json
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			grant_type		formData	string																							true	"Grant type: 'urn:ietf:params:oauth:grant-type:device_code' or 'refresh_token'"
//	@Param			device_code		formData	string																							false	"Device code (required when grant_type=device_code)"
//	@Param			client_id		formData	string																							true	"OAuth client ID"
//	@Param			refresh_token	formData	string																							false	"Refresh token (required when grant_type=refresh_token)"
//	@Success		200				{object}	object{access_token=string,refresh_token=string,token_type=string,expires_in=int,scope=string}	"Access token issued successfully"
//	@Failure		400				{object}	object{error=string,error_description=string}													"Invalid request (unsupported_grant_type, invalid_request, authorization_pending, slow_down, expired_token, access_denied, invalid_grant)"
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Supported grant types: device_code, refresh_token, authorization_code, client_credentials",
		})
	}
}

// handleDeviceCodeGrant handles device code grant type (RFC 8628)
func (h *TokenHandler) handleDeviceCodeGrant(c *gin.Context) {
	deviceCode := c.PostForm("device_code")
	clientID := c.PostForm("client_id")

	if deviceCode == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_code and client_id are required",
		})
		return
	}

	accessToken, refreshToken, err := h.tokenService.ExchangeDeviceCode(
		c.Request.Context(),
		deviceCode,
		clientID,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrAuthorizationPending):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "authorization_pending",
			})
		case errors.Is(err, services.ErrSlowDown):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "slow_down",
			})
		case errors.Is(err, services.ErrExpiredToken):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "expired_token",
			})
		case errors.Is(err, services.ErrAccessDenied):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "access_denied",
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken.Token,
		"refresh_token": refreshToken.Token,
		"token_type":    accessToken.TokenType,
		"expires_in":    int(h.config.JWTExpiration.Seconds()),
		"scope":         accessToken.Scopes,
	})
}

// handleRefreshTokenGrant handles refresh token grant type (RFC 6749)
func (h *TokenHandler) handleRefreshTokenGrant(c *gin.Context) {
	// 1. Parse parameters
	refreshTokenString := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	requestedScopes := c.PostForm("scope") // Optional

	// 2. Validate required parameters
	if refreshTokenString == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "refresh_token and client_id are required",
		})
		return
	}

	// 3. Call service to refresh token
	newAccessToken, newRefreshToken, err := h.tokenService.RefreshAccessToken(
		c.Request.Context(),
		refreshTokenString,
		clientID,
		requestedScopes,
	)
	// 4. Error handling (RFC 6749 error codes)
	if err != nil {
		switch {
		case errors.Is(err, token.ErrInvalidRefreshToken),
			errors.Is(err, token.ErrExpiredRefreshToken):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "Refresh token is invalid or expired",
			})
		case errors.Is(err, services.ErrAccessDenied):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Client authentication failed",
			})
		case errors.Is(err, token.ErrInvalidScope):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "Requested scope exceeds original grant",
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Token refresh failed",
			})
		}
		return
	}

	// 5. Return new tokens (RFC 6749 format)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken.Token,
		"refresh_token": newRefreshToken.Token,
		"token_type":    newAccessToken.TokenType,
		"expires_in":    int(h.config.JWTExpiration.Seconds()),
		"scope":         newAccessToken.Scopes,
	})
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
//	@Success		200				{object}	object{active=bool,user_id=string,client_id=string,scope=string,exp=int,iss=string}	"Token is valid"
//	@Failure		401				{object}	object{error=string,error_description=string}										"Token is invalid or expired (missing_token, invalid_token)"
//	@Router			/oauth/tokeninfo [get]
func (h *TokenHandler) TokenInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "missing_token",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	result, err := h.tokenService.ValidateToken(c.Request.Context(), tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": err.Error(),
		})
		return
	}

	// Identify whether this is a user-delegated token or a machine (client credentials) token
	subjectType := "user"
	if strings.HasPrefix(result.UserID, "client:") {
		subjectType = "client"
	}

	c.JSON(http.StatusOK, gin.H{
		"active":       result.Valid,
		"user_id":      result.UserID,
		"client_id":    result.ClientID,
		"scope":        result.Scopes,
		"exp":          result.ExpiresAt.Unix(),
		"iss":          h.config.BaseURL,
		"subject_type": subjectType,
	})
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "token parameter is required",
		})
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
	// Prefer HTTP Basic Auth; fall back to form-body parameters
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		c.Header("WWW-Authenticate", `Basic realm="authgate"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication required: use HTTP Basic Auth or provide client_id and client_secret in the request body",
		})
		return
	}

	requestedScopes := c.PostForm("scope") // Optional

	accessToken, err := h.tokenService.IssueClientCredentialsToken(
		c.Request.Context(),
		clientID,
		clientSecret,
		requestedScopes,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidClientCredentials),
			errors.Is(err, services.ErrClientNotConfidential):
			// RFC 6749 §5.2: use 401 + WWW-Authenticate for invalid_client
			c.Header("WWW-Authenticate", `Basic realm="authgate"`)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": "Client authentication failed",
			})
		case errors.Is(err, services.ErrClientCredentialsFlowDisabled):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "unauthorized_client",
				"error_description": "Client credentials flow is not enabled for this client",
			})
		case errors.Is(err, token.ErrInvalidScope):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "Requested scope exceeds client permissions or contains restricted scopes (openid, offline_access are not permitted)",
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Token issuance failed",
			})
		}
		return
	}

	// RFC 6749 §4.4.3: response MUST NOT include a refresh_token
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken.Token,
		"token_type":   accessToken.TokenType,
		"expires_in":   int(time.Until(accessToken.ExpiresAt).Seconds()),
		"scope":        accessToken.Scopes,
	})
}

// handleAuthorizationCodeGrant handles the authorization_code grant type (RFC 6749 §4.1.3).
func (h *TokenHandler) handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret") // Empty for public clients
	codeVerifier := c.PostForm("code_verifier") // PKCE; empty for confidential clients

	if code == "" || redirectURI == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "code, redirect_uri, and client_id are required",
		})
		return
	}

	// Validate and consume the authorization code
	authCode, err := h.authorizationService.ExchangeCode(
		c.Request.Context(),
		code, clientID, redirectURI, clientSecret, codeVerifier,
	)
	if err != nil {
		errCode := errInvalidGrant
		if errors.Is(err, services.ErrUnauthorizedClient) {
			errCode = "unauthorized_client"
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errCode,
			"error_description": err.Error(),
		})
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

	// Issue access + refresh tokens (+ ID token when openid scope was granted)
	accessToken, refreshToken, idToken, err := h.tokenService.ExchangeAuthorizationCode(
		c.Request.Context(),
		authCode,
		authorizationID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to issue tokens",
		})
		return
	}

	resp := gin.H{
		"access_token": accessToken.Token,
		"token_type":   accessToken.TokenType,
		"expires_in":   int(time.Until(accessToken.ExpiresAt).Seconds()),
		"scope":        accessToken.Scopes,
	}
	if refreshToken != nil && h.config.EnableRefreshTokens {
		resp["refresh_token"] = refreshToken.Token
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}

	c.JSON(http.StatusOK, resp)
}
