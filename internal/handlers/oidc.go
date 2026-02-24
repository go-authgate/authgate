package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/services"

	"github.com/gin-gonic/gin"
)

// OIDCHandler handles OIDC Discovery and UserInfo endpoints.
type OIDCHandler struct {
	tokenService *services.TokenService
	userService  *services.UserService
	config       *config.Config
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(
	ts *services.TokenService,
	us *services.UserService,
	cfg *config.Config,
) *OIDCHandler {
	return &OIDCHandler{
		tokenService: ts,
		userService:  us,
		config:       cfg,
	}
}

// discoveryMetadata holds the OIDC Provider Metadata returned by the discovery endpoint.
type discoveryMetadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

// Discovery godoc
//
//	@Summary		OIDC Discovery
//	@Description	OpenID Connect Provider Metadata (RFC 8414 / OIDC Discovery 1.0)
//	@Tags			OIDC
//	@Produce		json
//	@Success		200	{object}	discoveryMetadata	"Provider metadata"
//	@Router			/.well-known/openid-configuration [get]
func (h *OIDCHandler) Discovery(c *gin.Context) {
	base := strings.TrimRight(h.config.BaseURL, "/")
	meta := discoveryMetadata{
		Issuer:                           base,
		AuthorizationEndpoint:            base + "/oauth/authorize",
		TokenEndpoint:                    base + "/oauth/token",
		UserinfoEndpoint:                 base + "/oauth/userinfo",
		RevocationEndpoint:               base + "/oauth/revoke",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"HS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "read", "write"},
		TokenEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			GrantTypeDeviceCode,
			GrantTypeRefreshToken,
		},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"name",
			"preferred_username",
			"email",
			"email_verified",
			"picture",
			"updated_at",
		},
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	c.JSON(http.StatusOK, meta)
}

// UserInfo godoc
//
//	@Summary		UserInfo Endpoint
//	@Description	Returns claims about the authenticated end-user (OIDC Core 1.0 §5.3). Supports both GET and POST.
//	@Tags			OIDC
//	@Produce		json
//	@Security		BearerAuth
//	@Param			Authorization	header		string											true	"Bearer token"
//	@Success		200				{object}	object											"User claims (sub, name, email, etc.)"
//	@Failure		401				{object}	object{error=string,error_description=string}	"Invalid or missing Bearer token"
//	@Router			/oauth/userinfo [get]
//	@Router			/oauth/userinfo [post]
func (h *OIDCHandler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Bearer token required",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	result, err := h.tokenService.ValidateToken(c.Request.Context(), tokenString)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": err.Error(),
		})
		return
	}

	user, err := h.userService.GetUserByID(result.UserID)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "User not found",
		})
		return
	}

	claims := buildUserInfoClaims(
		result.UserID,
		strings.TrimRight(h.config.BaseURL, "/"),
		result.Scopes,
		user.FullName,
		user.Username,
		user.AvatarURL,
		user.Email,
		user.UpdatedAt,
	)
	c.JSON(http.StatusOK, claims)
}

// buildUserInfoClaims constructs UserInfo response claims based on the granted scopes.
// sub and iss are always included. profile and email scopes gate their respective claims.
func buildUserInfoClaims(
	userID string,
	issuer string,
	scopes string,
	fullName string,
	username string,
	avatarURL string,
	email string,
	updatedAt time.Time,
) map[string]any {
	scopeSet := parseScopeSet(scopes)

	claims := map[string]any{
		"sub": userID,
		"iss": issuer,
	}

	if scopeSet["profile"] {
		claims["name"] = fullName
		claims["preferred_username"] = username
		if avatarURL != "" {
			claims["picture"] = avatarURL
		}
		claims["updated_at"] = updatedAt.Unix()
	}

	if scopeSet["email"] {
		claims["email"] = email
		claims["email_verified"] = false
	}

	return claims
}

// parseScopeSet converts a space-separated scope string into a boolean set.
func parseScopeSet(scopes string) map[string]bool {
	set := make(map[string]bool)
	for s := range strings.FieldsSeq(scopes) {
		set[s] = true
	}
	return set
}
