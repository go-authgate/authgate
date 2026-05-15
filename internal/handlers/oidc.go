package handlers

import (
	"net/http"
	"strings"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-gonic/gin"
)

// OIDCHandler handles OIDC Discovery and UserInfo endpoints.
type OIDCHandler struct {
	tokenService     *services.TokenService
	userService      *services.UserService
	config           *config.Config
	issuerURL        string // BaseURL with trailing slash stripped, computed once
	jwksAvailable    bool   // true when JWKS endpoint has at least one public key
	idTokenSupported bool   // true when the token provider can generate ID tokens
	// baseMeta is the shared core for /.well-known/openid-configuration and
	// /.well-known/oauth-authorization-server. Computed once at construction
	// because every input is fixed for the process lifetime.
	baseMeta baseMetadata
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(
	ts *services.TokenService,
	us *services.UserService,
	cfg *config.Config,
	jwksAvailable bool,
	idTokenSupported bool,
) *OIDCHandler {
	h := &OIDCHandler{
		tokenService:     ts,
		userService:      us,
		config:           cfg,
		issuerURL:        strings.TrimRight(cfg.BaseURL, "/"),
		jwksAvailable:    jwksAvailable,
		idTokenSupported: idTokenSupported,
	}
	h.baseMeta = h.buildBaseMetadata()
	return h
}

// discoveryMetadata holds the OIDC Provider Metadata returned by the discovery endpoint.
type discoveryMetadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	JwksURI                          string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

// oauthASMetadata is the curated OAuth 2.0 Authorization Server Metadata
// (RFC 8414) shape. It mirrors the OIDC discovery payload minus OIDC-only
// fields (userinfo, id_token signing algs, subject_types, OIDC claims) and
// adds OAuth-specific fields (introspection, revocation_endpoint_auth_methods,
// dynamic client registration when enabled). MCP clients try this endpoint
// first per the MCP authorization spec.
type oauthASMetadata struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	IntrospectionEndpoint                  string   `json:"introspection_endpoint"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	RegistrationEndpoint                   string   `json:"registration_endpoint,omitempty"`
	DeviceAuthorizationEndpoint            string   `json:"device_authorization_endpoint"`
	JwksURI                                string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ScopesSupported                        []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethods       []string `json:"introspection_endpoint_auth_methods_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	// RFC 8707 §3 — advertise that the `resource` request parameter is
	// honored on /authorize and /token. Always true for this server.
	// Two field names are emitted because the RFC 8707 draft used
	// `resource_parameter_supported` while the IANA OAuth metadata registry
	// (and most large OAuth providers — Auth0, Okta, AWS Cognito) settled
	// on `resource_indicators_supported`. Emitting both keeps both client
	// generations interoperable.
	ResourceIndicatorsSupported bool `json:"resource_indicators_supported"`
	ResourceParameterSupported  bool `json:"resource_parameter_supported"`
}

// baseMetadata holds the shared core both Discovery and
// OAuthAuthorizationServerMetadata derive from: issuer, endpoint URLs, supported
// response types / grants / auth methods / scopes, and PKCE methods. OIDC- and
// OAuth-specific decoration happens in the respective handlers.
type baseMetadata struct {
	Issuer                      string
	AuthorizationEndpoint       string
	TokenEndpoint               string
	UserinfoEndpoint            string
	RevocationEndpoint          string
	IntrospectionEndpoint       string
	RegistrationEndpoint        string // empty when DCR disabled
	DeviceAuthorizationEndpoint string
	JwksURI                     string // empty when no JWKS
	ResponseTypesSupported      []string
	ScopesSupported             []string
	TokenEndpointAuthMethods    []string
	// IntrospectionEndpointAuthMethods is narrower than the token-endpoint
	// set because /oauth/introspect requires client authentication — it
	// rejects `none`. Advertising `none` here would invite unauthenticated
	// introspection attempts that the server immediately 401s.
	IntrospectionEndpointAuthMethods []string
	// RevocationEndpointAuthMethods reflects /oauth/revoke's actual behavior:
	// it does NOT authenticate the calling client (just hashes the supplied
	// token and revokes it). Advertising `client_secret_basic`/
	// `client_secret_post` here would mislead RFC 8414 clients into
	// expecting auth that isn't enforced — so we publish only `none`.
	RevocationEndpointAuthMethods []string
	GrantTypesSupported           []string
	CodeChallengeMethodsSupported []string
	IDTokenSigningAlgValues       []string // empty when ID token not supported
}

// buildBaseMetadata returns the shared core used by both discovery endpoints.
func (h *OIDCHandler) buildBaseMetadata() baseMetadata {
	alg := h.config.JWTSigningAlgorithm
	if alg == "" {
		alg = config.AlgHS256
	}

	scopes := []string{"read", "write"}
	var idTokenAlgs []string
	if h.idTokenSupported {
		scopes = append([]string{"openid", "profile", "email"}, scopes...)
		idTokenAlgs = []string{alg}
	}

	m := baseMetadata{
		Issuer:                      h.issuerURL,
		AuthorizationEndpoint:       h.issuerURL + "/oauth/authorize",
		TokenEndpoint:               h.issuerURL + "/oauth/token",
		UserinfoEndpoint:            h.issuerURL + "/oauth/userinfo",
		RevocationEndpoint:          h.issuerURL + "/oauth/revoke",
		IntrospectionEndpoint:       h.issuerURL + "/oauth/introspect",
		DeviceAuthorizationEndpoint: h.issuerURL + "/oauth/device/code",
		ResponseTypesSupported:      []string{"code"},
		ScopesSupported:             scopes,
		TokenEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
		IntrospectionEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
		},
		// /oauth/revoke does not authenticate clients (see field docstring).
		RevocationEndpointAuthMethods: []string{"none"},
		GrantTypesSupported: []string{
			GrantTypeAuthorizationCode,
			GrantTypeDeviceCode,
			GrantTypeRefreshToken,
			GrantTypeClientCredentials,
		},
		CodeChallengeMethodsSupported: []string{"S256"},
		IDTokenSigningAlgValues:       idTokenAlgs,
	}
	if h.config.EnableDynamicClientRegistration {
		m.RegistrationEndpoint = h.issuerURL + "/oauth/register"
	}
	if h.jwksAvailable {
		m.JwksURI = h.issuerURL + "/.well-known/jwks.json"
	}
	return m
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
	base := h.baseMeta

	meta := discoveryMetadata{
		Issuer:                           base.Issuer,
		AuthorizationEndpoint:            base.AuthorizationEndpoint,
		TokenEndpoint:                    base.TokenEndpoint,
		UserinfoEndpoint:                 base.UserinfoEndpoint,
		RevocationEndpoint:               base.RevocationEndpoint,
		JwksURI:                          base.JwksURI,
		ResponseTypesSupported:           base.ResponseTypesSupported,
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: base.IDTokenSigningAlgValues,
		ScopesSupported:                  base.ScopesSupported,
		TokenEndpointAuthMethods:         base.TokenEndpointAuthMethods,
		GrantTypesSupported:              base.GrantTypesSupported,
		ClaimsSupported: []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"jti",
			"auth_time",
			"nonce",
			"at_hash",
			"name",
			"preferred_username",
			"email",
			"email_verified",
			"picture",
			"updated_at",
		},
		CodeChallengeMethodsSupported: base.CodeChallengeMethodsSupported,
	}

	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, meta)
}

// OAuthAuthorizationServerMetadata godoc
//
//	@Summary		OAuth 2.0 Authorization Server Metadata (RFC 8414)
//	@Description	Curated OAuth-only authorization server metadata. MCP clients
//	@Description	(modelcontextprotocol.io) try this endpoint first.
//	@Tags			OAuth
//	@Produce		json
//	@Success		200	{object}	oauthASMetadata	"AS metadata"
//	@Router			/.well-known/oauth-authorization-server [get]
func (h *OIDCHandler) OAuthAuthorizationServerMetadata(c *gin.Context) {
	base := h.baseMeta

	meta := oauthASMetadata{
		Issuer:                      base.Issuer,
		AuthorizationEndpoint:       base.AuthorizationEndpoint,
		TokenEndpoint:               base.TokenEndpoint,
		IntrospectionEndpoint:       base.IntrospectionEndpoint,
		RevocationEndpoint:          base.RevocationEndpoint,
		RegistrationEndpoint:        base.RegistrationEndpoint,
		DeviceAuthorizationEndpoint: base.DeviceAuthorizationEndpoint,
		JwksURI:                     base.JwksURI,
		ResponseTypesSupported:      base.ResponseTypesSupported,
		ScopesSupported:             base.ScopesSupported,
		// Three endpoints, three auth-method sets — advertised to match what
		// each handler actually enforces:
		//   - Token: accepts client_secret_basic/_post (confidential) plus
		//     none (public-client PKCE).
		//   - Introspection: confidential only — /oauth/introspect rejects
		//     `none` and 401s.
		//   - Revocation: /oauth/revoke does not authenticate the caller at
		//     all; advertising basic/_post would mislead RFC 8414 clients
		//     into expecting auth that isn't enforced.
		TokenEndpointAuthMethodsSupported:      base.TokenEndpointAuthMethods,
		RevocationEndpointAuthMethodsSupported: base.RevocationEndpointAuthMethods,
		IntrospectionEndpointAuthMethods:       base.IntrospectionEndpointAuthMethods,
		GrantTypesSupported:                    base.GrantTypesSupported,
		CodeChallengeMethodsSupported:          base.CodeChallengeMethodsSupported,
		ResourceIndicatorsSupported:            true,
		ResourceParameterSupported:             true,
	}

	c.Header("Cache-Control", "public, max-age=3600")
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
			"error":             errInvalidToken,
			"error_description": "Bearer token required",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	result, err := h.tokenService.ValidateToken(c.Request.Context(), tokenString)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             errInvalidToken,
			"error_description": err.Error(),
		})
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), result.UserID)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             errInvalidToken,
			"error_description": "User not found",
		})
		return
	}

	claims := buildUserInfoClaims(result.UserID, h.issuerURL, result.Scopes, user)
	c.JSON(http.StatusOK, claims)
}

// buildUserInfoClaims constructs UserInfo response claims based on the granted scopes.
// sub and iss are always included. profile and email scopes gate their respective claims.
func buildUserInfoClaims(userID, issuer, scopes string, user *models.User) map[string]any {
	scopeSet := util.ScopeSet(scopes)

	claims := map[string]any{
		"sub": userID,
		"iss": issuer,
	}

	if scopeSet["profile"] {
		claims["name"] = user.FullName
		claims["preferred_username"] = user.Username
		if user.AvatarURL != "" {
			claims["picture"] = user.AvatarURL
		}
		claims["updated_at"] = user.UpdatedAt.Unix()
	}

	if scopeSet["email"] {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}

	return claims
}
