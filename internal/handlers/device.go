package handlers

import (
	"errors"
	"log"
	"net/http"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// deviceCodeErrorMessage maps device code service errors to user-facing messages.
func deviceCodeErrorMessage(err error) string {
	switch {
	case errors.Is(err, services.ErrUserCodeNotFound):
		return "User code not found"
	case errors.Is(err, services.ErrDeviceCodeExpired):
		return "Code has expired, please request a new one"
	case errors.Is(err, services.ErrDeviceCodeAlreadyAuthorized):
		return "This code has already been authorized"
	default:
		return "Invalid or expired code"
	}
}

// renderDeviceErrorPage renders the device page with an error message.
func renderDeviceErrorPage(
	c *gin.Context,
	user *models.User,
	userCode, clientName, errorMsg string,
	statusCode int,
) {
	props := templates.DevicePageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, user, "device"),
		Username:    user.Username,
		UserCode:    userCode,
		ClientName:  clientName,
		Error:       errorMsg,
	}
	templates.RenderTempl(c, statusCode, templates.DevicePage(props))
}

type DeviceHandler struct {
	deviceService        *services.DeviceService
	userService          *services.UserService
	authorizationService *services.AuthorizationService
	config               *config.Config
}

func NewDeviceHandler(
	ds *services.DeviceService,
	us *services.UserService,
	as *services.AuthorizationService,
	cfg *config.Config,
) *DeviceHandler {
	return &DeviceHandler{deviceService: ds, userService: us, authorizationService: as, config: cfg}
}

// DeviceCodeRequest godoc
//
//	@Summary		Request device code
//	@Description	Request a device code for OAuth 2.0 device authorization flow (RFC 8628). This endpoint is called by CLI applications to initiate the device flow.
//	@Tags			OAuth
//	@Accept			json
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			client_id	formData	string																																true	"OAuth client ID"
//	@Param			scope		formData	string																																false	"Requested scopes (space-separated, default: 'email profile')"
//	@Param			resource	formData	[]string																															false	"RFC 8707 Resource Indicator(s) — bound to the issued JWT 'aud'. Repeat to send multiple."	collectionFormat(multi)
//	@Success		200			{object}	object{device_code=string,user_code=string,verification_uri=string,verification_uri_complete=string,expires_in=int,interval=int}	"Device code generated successfully"
//	@Failure		400			{object}	object{error=string,error_description=string}																						"Invalid request (invalid_client, invalid_target)"
//	@Failure		429			{object}	object{error=string,error_description=string}																						"Rate limit exceeded"
//	@Failure		500			{object}	object{error=string,error_description=string}																						"Internal server error"
//	@Router			/oauth/device/code [post]
func (h *DeviceHandler) DeviceCodeRequest(c *gin.Context) {
	clientID := c.PostForm("client_id")
	resource := c.PostFormArray("resource")
	if clientID == "" {
		// Also try JSON body
		var req struct {
			ClientID string   `json:"client_id"`
			Scope    string   `json:"scope"`
			Resource []string `json:"resource"`
		}
		if err := c.ShouldBindJSON(&req); err == nil {
			clientID = req.ClientID
			if req.Scope != "" {
				c.Set("scope", req.Scope)
			}
			if len(req.Resource) > 0 {
				resource = req.Resource
			}
		}
	}

	if clientID == "" {
		respondOAuthError(c, http.StatusBadRequest, errInvalidRequest, "client_id is required")
		return
	}

	scope := c.PostForm("scope")
	if scope == "" {
		if s, exists := c.Get("scope"); exists {
			scope = s.(string)
		} else {
			scope = "email profile"
		}
	}

	// RFC 8707 Resource Indicators: bind the audience the user is about to
	// authorize. Validating here (and persisting on the device code) prevents
	// the polling client from later picking or changing the `aud` at
	// /oauth/token after the user has already approved the device code.
	validatedResource, err := util.ValidateResourceIndicators(resource)
	if err != nil {
		respondOAuthError(c, http.StatusBadRequest, errInvalidTarget, err.Error())
		return
	}

	dc, err := h.deviceService.GenerateDeviceCode(
		c.Request.Context(),
		clientID,
		scope,
		validatedResource,
	)
	if err != nil {
		if errors.Is(err, services.ErrInvalidClient) {
			respondOAuthError(c, http.StatusBadRequest, errInvalidClient, "Unknown client_id")
			return
		}
		if errors.Is(err, services.ErrClientInactive) {
			respondOAuthError(c, http.StatusBadRequest, errInvalidClient, "Client is inactive")
			return
		}
		if errors.Is(err, services.ErrDeviceFlowNotEnabled) {
			respondOAuthError(
				c,
				http.StatusBadRequest,
				errUnauthorizedClient,
				"Device authorization flow is not enabled for this client",
			)
			return
		}
		log.Printf("[device] device code generation error: %v", err)
		respondOAuthError(
			c,
			http.StatusInternalServerError,
			errServerError,
			"An internal error occurred",
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"device_code":      dc.DeviceCode,
		"user_code":        services.FormatUserCode(dc.UserCode),
		"verification_uri": h.config.BaseURL + "/device",
		"verification_uri_complete": h.config.BaseURL + "/device?user_code=" + services.FormatUserCode(
			dc.UserCode,
		),
		"expires_in": int(h.config.DeviceCodeExpiration.Seconds()),
		"interval":   dc.Interval,
	})
}

// DevicePage renders the device code input page
func (h *DeviceHandler) DevicePage(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get(SessionUserID)
	userCode := c.Query("user_code")

	// Get user info from database
	var user *models.User
	if userID != nil {
		user, _ = h.userService.GetUserByID(c.Request.Context(), userID.(string))
	}
	if user == nil {
		user = &models.User{} // zero-value for unauthenticated visitors
	}

	clientName := ""
	var resource []string
	if userCode != "" {
		client, dc, err := h.deviceService.GetClientByUserCode(c.Request.Context(), userCode)
		if err == nil {
			clientName = client.ClientName
			resource = []string(dc.Resource)
		}
	}

	templates.RenderTempl(c, http.StatusOK, templates.DevicePage(templates.DevicePageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, user, "device"),
		Username:    user.Username,
		UserCode:    userCode,
		ClientName:  clientName,
		Resource:    resource,
		Error:       "",
	}))
}

// DeviceVerify handles the user code verification and authorization
func (h *DeviceHandler) DeviceVerify(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get(SessionUserID)
	if userID == nil {
		c.Redirect(http.StatusFound, "/login?redirect=/device")
		return
	}

	userCode := c.PostForm("user_code")

	user, _ := h.userService.GetUserByID(c.Request.Context(), userID.(string))
	if user == nil {
		user = &models.User{}
	}

	if userCode == "" {
		renderDeviceErrorPage(c, user, "", "", "Please enter a user code", http.StatusBadRequest)
		return
	}

	// Get client and device code before authorizing
	client, dc, err := h.deviceService.GetClientByUserCode(c.Request.Context(), userCode)
	if err != nil {
		renderDeviceErrorPage(
			c,
			user,
			userCode,
			"",
			deviceCodeErrorMessage(err),
			http.StatusBadRequest,
		)
		return
	}

	if !client.IsActive() {
		renderDeviceErrorPage(
			c,
			user,
			userCode,
			"",
			"This application is not active",
			http.StatusBadRequest,
		)
		return
	}
	clientName := client.ClientName

	// Resource-bound device codes require an explicit confirmation step that
	// surfaces both the client and the requested resource(s) before
	// authorization. The verification_uri_complete flow already shows them on
	// the GET /device page, but the manual-entry flow (user types user_code
	// into the form on /device) would otherwise authorize as soon as they
	// click the submit button — without the user having ever seen the
	// audience they were about to grant. Routing through this confirm page
	// makes the audience binding genuinely user-attested for both flows.
	if len(dc.Resource) > 0 && c.PostForm("confirmed") != "true" {
		templates.RenderTempl(
			c,
			http.StatusOK,
			templates.DeviceConfirmPage(templates.DeviceConfirmPageProps{
				BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: buildNavbarProps(c, user, "device"),
				Username:    user.Username,
				UserCode:    userCode,
				ClientName:  clientName,
				Resource:    []string(dc.Resource),
			}),
		)
		return
	}

	// Record the user's consent BEFORE flipping the device code to authorized.
	// AuthorizeDeviceCode unblocks the polling /oauth/token grant; if we ran
	// it first, a fast polling client could exchange the device code in the
	// window between AuthorizeDeviceCode and SaveUserAuthorization and
	// receive tokens without an AuthorizationID FK — defeating the
	// cascade-revoke this consent row exists to enable. The reverse order
	// makes the UA visible to ExchangeDeviceCode no matter how tight the
	// poll loop is. (UserAuthorization is also resource-aware, so the access
	// token's `aud` matches the resource the user just approved.)
	if _, err := h.authorizationService.SaveUserAuthorization(
		c.Request.Context(),
		userID.(string),
		client.ID,
		client.ClientID,
		dc.Scopes,
		[]string(dc.Resource),
	); err != nil {
		renderDeviceErrorPage(
			c,
			user,
			userCode,
			clientName,
			"Failed to save authorization",
			http.StatusInternalServerError,
		)
		return
	}

	err = h.deviceService.AuthorizeDeviceCode(
		c.Request.Context(),
		userCode,
		userID.(string),
		user.Username,
	)
	if err != nil {
		renderDeviceErrorPage(
			c,
			user,
			userCode,
			clientName,
			deviceCodeErrorMessage(err),
			http.StatusBadRequest,
		)
		return
	}

	templates.RenderTempl(c, http.StatusOK, templates.SuccessPage(templates.SuccessPageProps{
		BaseProps:  templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		Username:   user.Username,
		ClientName: clientName,
	}))
}
