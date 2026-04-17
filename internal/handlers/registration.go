package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"

	"github.com/gin-gonic/gin"
)

// RegistrationHandler handles Dynamic Client Registration (RFC 7591).
type RegistrationHandler struct {
	clientService *services.ClientService
	auditService  core.AuditLogger
	config        *config.Config
}

// NewRegistrationHandler creates a new RegistrationHandler.
func NewRegistrationHandler(
	cs *services.ClientService,
	auditSvc core.AuditLogger,
	cfg *config.Config,
) *RegistrationHandler {
	return &RegistrationHandler{
		clientService: cs,
		auditService:  auditSvc,
		config:        cfg,
	}
}

// clientRegistrationRequest represents the RFC 7591 §2 registration request body.
type clientRegistrationRequest struct {
	ClientName            string          `json:"client_name"`
	RedirectURIs          []string        `json:"redirect_uris"`
	GrantTypes            []string        `json:"grant_types"`
	TokenEPAuth           string          `json:"token_endpoint_auth_method"`
	Scope                 string          `json:"scope"`
	ClientURI             string          `json:"client_uri"`
	JWKSURI               string          `json:"jwks_uri,omitempty"`
	JWKS                  json.RawMessage `json:"jwks,omitempty"`
	TokenEPAuthSigningAlg string          `json:"token_endpoint_auth_signing_alg,omitempty"`
}

// Register godoc
//
//	@Summary		Register a new OAuth client (RFC 7591)
//	@Description	Dynamically register a new OAuth 2.0 client. Must be enabled via ENABLE_DYNAMIC_CLIENT_REGISTRATION=true. Registered clients start in "pending" status and require admin approval before use.
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		clientRegistrationRequest															true	"Client registration request"
//	@Success		201		{object}	object{client_id=string,client_secret=string,client_secret_expires_at=int,jwks_uri=string,token_endpoint_auth_signing_alg=string,client_name=string,redirect_uris=[]string,grant_types=[]string,token_endpoint_auth_method=string,scope=string,client_id_issued_at=int}	"Client registered successfully. client_secret and client_secret_expires_at are only present for client_secret_basic/post auth methods; jwks_uri and token_endpoint_auth_signing_alg are present for private_key_jwt."
//	@Failure		400		{object}	object{error=string,error_description=string}											"Invalid client metadata"
//	@Failure		401		{object}	object{error=string,error_description=string}											"Invalid or missing initial access token"
//	@Failure		403		{object}	object{error=string,error_description=string}											"Dynamic registration is disabled"
//	@Failure		429		{object}	object{error=string,error_description=string}											"Rate limit exceeded"
//	@Failure		500		{object}	object{error=string,error_description=string}											"Internal server error"
//	@Router			/oauth/register [post]
func (h *RegistrationHandler) Register(c *gin.Context) {
	// 1. Check if dynamic registration is enabled
	if !h.config.EnableDynamicClientRegistration {
		respondOAuthError(
			c,
			http.StatusForbidden,
			"registration_not_supported",
			"Dynamic client registration is not enabled on this server",
		)
		return
	}

	// 2. Validate initial access token (RFC 7591 §1.1 Protected Registration)
	if h.config.DynamicClientRegistrationToken != "" {
		if !validateRegistrationToken(c, h.config.DynamicClientRegistrationToken) {
			return
		}
	}

	// 3. Parse request body (RFC 7591 §2)
	var req clientRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondOAuthError(
			c,
			http.StatusBadRequest,
			"invalid_client_metadata",
			"Invalid request body: "+err.Error(),
		)
		return
	}

	// 4. Validate client_name (required)
	if strings.TrimSpace(req.ClientName) == "" {
		respondOAuthError(
			c,
			http.StatusBadRequest,
			"invalid_client_metadata",
			"client_name is required",
		)
		return
	}

	// 5. Determine grant types from request
	enableDeviceFlow := false
	enableAuthCodeFlow := false
	enableClientCredentials := false

	if len(req.GrantTypes) == 0 {
		// RFC 7591 §2: default grant_type is "authorization_code", except
		// private_key_jwt registrations typically target the client_credentials
		// flow — skip the redirect_uri requirement in that case.
		if req.TokenEPAuth == models.TokenEndpointAuthPrivateKeyJWT {
			enableClientCredentials = true
		} else {
			enableAuthCodeFlow = true
		}
	} else {
		for _, gt := range req.GrantTypes {
			switch gt {
			case GrantTypeAuthorizationCode:
				enableAuthCodeFlow = true
			case GrantTypeDeviceCode, GrantTypeDeviceCodeShort:
				enableDeviceFlow = true
			case GrantTypeClientCredentials:
				enableClientCredentials = true
			default:
				respondOAuthError(
					c,
					http.StatusBadRequest,
					"invalid_client_metadata",
					"Unsupported grant_type: "+gt+". Supported: authorization_code, device_code, client_credentials",
				)
				return
			}
		}
	}

	// 6. Determine auth method → client type (RFC 7591 §2: default is "client_secret_basic")
	authMethod := req.TokenEPAuth
	if authMethod == "" {
		authMethod = models.TokenEndpointAuthClientSecretBasic
	}

	var clientType core.ClientType
	switch authMethod {
	case models.TokenEndpointAuthNone:
		clientType = core.ClientTypePublic
	case models.TokenEndpointAuthClientSecretBasic, models.TokenEndpointAuthClientSecretPost:
		clientType = core.ClientTypeConfidential
	case models.TokenEndpointAuthPrivateKeyJWT:
		if !h.config.PrivateKeyJWTEnabled {
			respondOAuthError(
				c,
				http.StatusBadRequest,
				"invalid_client_metadata",
				"private_key_jwt is not enabled on this server",
			)
			return
		}
		clientType = core.ClientTypeConfidential
	default:
		respondOAuthError(
			c,
			http.StatusBadRequest,
			"invalid_client_metadata",
			"Unsupported token_endpoint_auth_method: "+req.TokenEPAuth+". Supported: none, client_secret_basic, client_secret_post, private_key_jwt",
		)
		return
	}

	// 6b. For private_key_jwt, require key material (RFC 7591 §2.1).
	var (
		jwksInline string
		signingAlg string
	)
	if authMethod == models.TokenEndpointAuthPrivateKeyJWT {
		hasURI := strings.TrimSpace(req.JWKSURI) != ""
		hasInline := len(req.JWKS) > 0 && !isJSONNull(req.JWKS)
		if !hasURI && !hasInline {
			respondOAuthError(
				c,
				http.StatusBadRequest,
				"invalid_client_metadata",
				"private_key_jwt requires either jwks_uri or jwks",
			)
			return
		}
		if hasURI && hasInline {
			respondOAuthError(
				c,
				http.StatusBadRequest,
				"invalid_client_metadata",
				"jwks_uri and jwks are mutually exclusive",
			)
			return
		}
		if hasInline {
			jwksInline = string(req.JWKS)
		}
		signingAlg = req.TokenEPAuthSigningAlg
		if signingAlg == "" {
			signingAlg = models.AssertionAlgRS256
		}
		if signingAlg != models.AssertionAlgRS256 && signingAlg != models.AssertionAlgES256 {
			respondOAuthError(
				c,
				http.StatusBadRequest,
				"invalid_client_metadata",
				"Unsupported token_endpoint_auth_signing_alg: "+req.TokenEPAuthSigningAlg+". Supported: RS256, ES256",
			)
			return
		}
	}

	// 7. Validate scopes (only user-safe scopes allowed)
	scope := strings.TrimSpace(req.Scope)
	if scope != "" {
		for s := range strings.FieldsSeq(scope) {
			switch s {
			case "email", "profile", "openid", "offline_access":
				// ok
			default:
				respondOAuthError(
					c,
					http.StatusBadRequest,
					"invalid_client_metadata",
					"Unsupported scope: "+s+". Allowed: email, profile, openid, offline_access",
				)
				return
			}
		}
	}

	// 8. Create the client via service (pending status, requires admin approval)
	createReq := services.CreateClientRequest{
		ClientName:                  req.ClientName,
		Description:                 req.ClientURI,
		Scopes:                      scope,
		RedirectURIs:                req.RedirectURIs,
		ClientType:                  clientType,
		EnableDeviceFlow:            enableDeviceFlow,
		EnableAuthCodeFlow:          enableAuthCodeFlow,
		IsAdminCreated:              false, // Dynamic registration → pending approval
		EnableClientCredentialsFlow: enableClientCredentials,
		TokenEndpointAuthMethod:     authMethod,
		TokenEndpointAuthSigningAlg: signingAlg,
		JWKSURI:                     req.JWKSURI,
		JWKS:                        jwksInline,
	}

	resp, err := h.clientService.CreateClient(c.Request.Context(), createReq)
	if err != nil {
		if isClientValidationError(err) {
			respondOAuthError(c, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		} else {
			respondOAuthError(
				c,
				http.StatusInternalServerError,
				errServerError,
				"Failed to register client",
			)
		}
		return
	}

	// 9. Log dynamic registration audit event
	app := resp.OAuthApplication
	h.auditService.Log(c.Request.Context(), core.AuditLogEntry{
		EventType:    models.EventClientRegistered,
		Severity:     models.SeverityInfo,
		ResourceType: models.ResourceClient,
		ResourceID:   app.ClientID,
		ResourceName: app.ClientName,
		Action:       "OAuth client registered via dynamic registration (RFC 7591)",
		Details: models.AuditDetails{
			"client_name":   app.ClientName,
			"grant_types":   app.GrantTypes,
			"scopes":        app.Scopes,
			"client_type":   app.ClientType,
			"client_uri":    req.ClientURI,
			"redirect_uris": app.RedirectURIs,
			"source_ip":     c.ClientIP(),
		},
		Success: true,
	})

	// 10. Build RFC 7591 §3.2.1 response
	grantTypes := buildResponseGrantTypes(app)

	response := gin.H{
		"client_id":                  app.ClientID,
		"client_name":                app.ClientName,
		"redirect_uris":              app.RedirectURIs,
		"grant_types":                grantTypes,
		"token_endpoint_auth_method": authMethod,
		"scope":                      app.Scopes,
		"client_id_issued_at":        app.CreatedAt.Unix(),
	}
	// Only client_secret_* clients receive a shared secret in the response.
	if app.UsesClientSecret() {
		response["client_secret"] = resp.ClientSecretPlain
		response["client_secret_expires_at"] = 0 // RFC 7591 §3.2.1: 0 = does not expire
	}
	if app.UsesPrivateKeyJWT() {
		if app.JWKSURI != "" {
			response["jwks_uri"] = app.JWKSURI
		}
		response["token_endpoint_auth_signing_alg"] = app.TokenEndpointAuthSigningAlg
	}
	c.JSON(http.StatusCreated, response)
}

// isJSONNull reports whether the given raw JSON represents the null literal
// (or only whitespace around it). Used to distinguish "jwks": null from a
// missing or present jwks field.
func isJSONNull(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

// buildResponseGrantTypes converts the OAuthApplication's enabled flows into
// RFC 7591 grant_types array.
func buildResponseGrantTypes(app *models.OAuthApplication) []string {
	var grantTypes []string
	if app.EnableDeviceFlow {
		grantTypes = append(grantTypes, GrantTypeDeviceCode)
	}
	if app.EnableAuthCodeFlow {
		grantTypes = append(grantTypes, GrantTypeAuthorizationCode)
	}
	if app.EnableClientCredentialsFlow {
		grantTypes = append(grantTypes, GrantTypeClientCredentials)
	}
	return grantTypes
}

// validateRegistrationToken checks the Authorization: Bearer <token> header
// against the configured initial access token (RFC 7591 §1.1 Protected Registration).
// Returns true if valid, false if rejected (response already written).
func validateRegistrationToken(c *gin.Context, expected string) bool {
	header := c.GetHeader("Authorization")
	if header == "" || !strings.HasPrefix(header, "Bearer ") {
		respondOAuthError(
			c,
			http.StatusUnauthorized,
			errInvalidToken,
			"An initial access token is required for client registration",
		)
		return false
	}

	token := strings.TrimPrefix(header, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		respondOAuthError(
			c,
			http.StatusUnauthorized,
			errInvalidToken,
			"The initial access token is invalid",
		)
		return false
	}

	return true
}

// isClientValidationError returns true if the error is a known client
// validation error (should be 400), false for internal errors (should be 500).
func isClientValidationError(err error) bool {
	return errors.Is(err, services.ErrClientNameRequired) ||
		errors.Is(err, services.ErrRedirectURIRequired) ||
		errors.Is(err, services.ErrInvalidRedirectURI) ||
		errors.Is(err, services.ErrInvalidClientData) ||
		errors.Is(err, services.ErrAtLeastOneGrantRequired)
}
