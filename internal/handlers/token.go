package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/token"

	"github.com/gin-gonic/gin"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	// https://datatracker.ietf.org/doc/html/rfc6749#section-6
	GrantTypeRefreshToken = "refresh_token"
)

type TokenHandler struct {
	tokenService *services.TokenService
	config       *config.Config
}

func NewTokenHandler(ts *services.TokenService, cfg *config.Config) *TokenHandler {
	return &TokenHandler{tokenService: ts, config: cfg}
}

// Token handles POST /oauth/token
// Routes to appropriate grant type handler based on grant_type parameter
func (h *TokenHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case GrantTypeDeviceCode:
		h.handleDeviceCodeGrant(c)
	case GrantTypeRefreshToken:
		h.handleRefreshTokenGrant(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Supported grant types: device_code, refresh_token",
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

	accessToken, refreshToken, err := h.tokenService.ExchangeDeviceCode(deviceCode, clientID)
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

// TokenInfo handles GET /oauth/tokeninfo (optional endpoint to validate tokens)
func (h *TokenHandler) TokenInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "missing_token",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	result, err := h.tokenService.ValidateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active":    result.Valid,
		"user_id":   result.UserID,
		"client_id": result.ClientID,
		"scope":     result.Scopes,
		"exp":       result.ExpiresAt.Unix(),
		"iss":       h.config.BaseURL,
	})
}

// Revoke handles POST /oauth/revoke (RFC 7009)
// This endpoint allows clients to revoke access tokens
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
