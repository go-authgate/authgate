package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"

	"github.com/gin-gonic/gin"
)

// RegistrationHandler handles Dynamic Client Registration (RFC 7591).
type RegistrationHandler struct {
	clientService *services.ClientService
	auditService  *services.AuditService
	config        *config.Config
}

// NewRegistrationHandler creates a new RegistrationHandler.
func NewRegistrationHandler(
	cs *services.ClientService,
	auditSvc *services.AuditService,
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
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	TokenEPAuth  string   `json:"token_endpoint_auth_method"`
	Scope        string   `json:"scope"`
	ClientURI    string   `json:"client_uri"`
}

// Register godoc
//
//	@Summary		Register a new OAuth client (RFC 7591)
//	@Description	Dynamically register a new OAuth 2.0 client. Must be enabled via ENABLE_DYNAMIC_CLIENT_REGISTRATION=true. Registered clients start in "pending" status and require admin approval before use.
//	@Tags			OAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		clientRegistrationRequest															true	"Client registration request"
//	@Success		201		{object}	object{client_id=string,client_secret=string,client_name=string,redirect_uris=[]string,grant_types=[]string,token_endpoint_auth_method=string,scope=string,client_id_issued_at=int,client_secret_expires_at=int}	"Client registered successfully"
//	@Failure		400		{object}	object{error=string,error_description=string}											"Invalid client metadata"
//	@Failure		403		{object}	object{error=string,error_description=string}											"Dynamic registration is disabled"
//	@Failure		429		{object}	object{error=string,error_description=string}											"Rate limit exceeded"
//	@Failure		500		{object}	object{error=string,error_description=string}											"Internal server error"
//	@Router			/oauth/register [post]
func (h *RegistrationHandler) Register(c *gin.Context) {
	// 1. Check if dynamic registration is enabled
	if !h.config.EnableDynamicClientRegistration {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "registration_not_supported",
			"error_description": "Dynamic client registration is not enabled on this server",
		})
		return
	}

	// 2. Parse request body (RFC 7591 §2)
	var req clientRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": "Invalid request body: " + err.Error(),
		})
		return
	}

	// 3. Validate client_name (required)
	if strings.TrimSpace(req.ClientName) == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": "client_name is required",
		})
		return
	}

	// 4. Determine grant types from request
	enableDeviceFlow := false
	enableAuthCodeFlow := false

	if len(req.GrantTypes) == 0 {
		// RFC 7591 §2: default grant_type is "authorization_code"
		enableAuthCodeFlow = true
	} else {
		for _, gt := range req.GrantTypes {
			switch gt {
			case "authorization_code":
				enableAuthCodeFlow = true
			case "urn:ietf:params:oauth:grant-type:device_code", "device_code":
				enableDeviceFlow = true
			default:
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_client_metadata",
					"error_description": "Unsupported grant_type: " + gt + ". Supported: authorization_code, device_code",
				})
				return
			}
		}
	}

	// 5. Determine auth method → client type (RFC 7591 §2: default is "client_secret_basic")
	authMethod := req.TokenEPAuth
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}

	var clientType string
	switch authMethod {
	case "none":
		clientType = services.ClientTypePublic
	case "client_secret_basic", "client_secret_post":
		clientType = services.ClientTypeConfidential
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": "Unsupported token_endpoint_auth_method: " + req.TokenEPAuth + ". Supported: none, client_secret_basic, client_secret_post",
		})
		return
	}

	// 6. Validate scopes (only user-safe scopes allowed)
	scope := strings.TrimSpace(req.Scope)
	if scope != "" {
		for s := range strings.FieldsSeq(scope) {
			switch s {
			case "email", "profile", "openid", "offline_access":
				// ok
			default:
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_client_metadata",
					"error_description": "Unsupported scope: " + s + ". Allowed: email, profile, openid, offline_access",
				})
				return
			}
		}
	}

	// 7. Create the client via service (pending status, requires admin approval)
	createReq := services.CreateClientRequest{
		ClientName:         req.ClientName,
		Description:        req.ClientURI,
		Scopes:             scope,
		RedirectURIs:       req.RedirectURIs,
		ClientType:         clientType,
		EnableDeviceFlow:   enableDeviceFlow,
		EnableAuthCodeFlow: enableAuthCodeFlow,
		IsAdminCreated:     false, // Dynamic registration → pending approval
	}

	resp, err := h.clientService.CreateClient(c.Request.Context(), createReq)
	if err != nil {
		if isClientValidationError(err) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client_metadata",
				"error_description": err.Error(),
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Failed to register client",
			})
		}
		return
	}

	// 8. Log dynamic registration audit event
	app := resp.OAuthApplication
	if h.auditService != nil {
		h.auditService.Log(c.Request.Context(), services.AuditLogEntry{
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
	}

	// 9. Build RFC 7591 §3.2.1 response
	grantTypes := buildResponseGrantTypes(app)

	c.JSON(http.StatusCreated, gin.H{
		"client_id":                  app.ClientID,
		"client_secret":              resp.ClientSecretPlain,
		"client_name":                app.ClientName,
		"redirect_uris":              app.RedirectURIs,
		"grant_types":                grantTypes,
		"token_endpoint_auth_method": authMethod,
		"scope":                      app.Scopes,
		"client_id_issued_at":        app.CreatedAt.Unix(),
		"client_secret_expires_at":   0, // 0 = does not expire (RFC 7591 §3.2.1)
	})
}

// buildResponseGrantTypes converts the OAuthApplication's enabled flows into
// RFC 7591 grant_types array.
func buildResponseGrantTypes(app *models.OAuthApplication) []string {
	var grantTypes []string
	if app.EnableDeviceFlow {
		grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:device_code")
	}
	if app.EnableAuthCodeFlow {
		grantTypes = append(grantTypes, "authorization_code")
	}
	if app.EnableClientCredentialsFlow {
		grantTypes = append(grantTypes, "client_credentials")
	}
	return grantTypes
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
