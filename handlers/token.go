package handlers

import (
	"net/http"
	"strings"

	"oauth-device-flow/config"
	"oauth-device-flow/services"

	"github.com/gin-gonic/gin"
)

const (
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
)

type TokenHandler struct {
	tokenService *services.TokenService
	config       *config.Config
}

func NewTokenHandler(ts *services.TokenService, cfg *config.Config) *TokenHandler {
	return &TokenHandler{tokenService: ts, config: cfg}
}

// Token handles POST /oauth/token
// This is called by the CLI to poll for the access token
func (h *TokenHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	if grantType != GrantTypeDeviceCode {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only device_code grant type is supported",
		})
		return
	}

	deviceCode := c.PostForm("device_code")
	clientID := c.PostForm("client_id")

	if deviceCode == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_code and client_id are required",
		})
		return
	}

	accessToken, err := h.tokenService.ExchangeDeviceCode(deviceCode, clientID)
	if err != nil {
		switch err {
		case services.ErrAuthorizationPending:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "authorization_pending",
			})
		case services.ErrSlowDown:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "slow_down",
			})
		case services.ErrExpiredToken:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "expired_token",
			})
		case services.ErrAccessDenied:
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
		"access_token": accessToken.Token,
		"token_type":   accessToken.TokenType,
		"expires_in":   int(h.config.JWTExpiration.Seconds()),
		"scope":        accessToken.Scopes,
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
	claims, err := h.tokenService.ValidateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active":    true,
		"user_id":   claims.UserID,
		"client_id": claims.ClientID,
		"scope":     claims.Scopes,
		"exp":       claims.ExpiresAt.Unix(),
		"iss":       claims.Issuer,
	})
}
