package handlers

import (
	"errors"
	"net/http"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/middleware"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/templates"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type DeviceHandler struct {
	deviceService *services.DeviceService
	userService   *services.UserService
	config        *config.Config
}

func NewDeviceHandler(
	ds *services.DeviceService,
	us *services.UserService,
	cfg *config.Config,
) *DeviceHandler {
	return &DeviceHandler{deviceService: ds, userService: us, config: cfg}
}

// DeviceCodeRequest handles POST /oauth/device/code
// This is called by the CLI to start the device flow
func (h *DeviceHandler) DeviceCodeRequest(c *gin.Context) {
	clientID := c.PostForm("client_id")
	if clientID == "" {
		// Also try JSON body
		var req struct {
			ClientID string `json:"client_id"`
			Scope    string `json:"scope"`
		}
		if err := c.ShouldBindJSON(&req); err == nil {
			clientID = req.ClientID
			if req.Scope != "" {
				c.Set("scope", req.Scope)
			}
		}
	}

	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	scope := c.PostForm("scope")
	if scope == "" {
		if s, exists := c.Get("scope"); exists {
			scope = s.(string)
		} else {
			scope = "read write"
		}
	}

	dc, err := h.deviceService.GenerateDeviceCode(c.Request.Context(), clientID, scope)
	if err != nil {
		if errors.Is(err, services.ErrInvalidClient) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Unknown client_id",
			})
			return
		}
		if errors.Is(err, services.ErrClientInactive) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Client is inactive",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": err.Error(),
		})
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
	username := session.Get(SessionUsername)
	userID := session.Get(SessionUserID)
	userCode := c.Query("user_code")

	usernameStr := ""
	if username != nil {
		usernameStr = username.(string)
	}

	isAdmin := false
	// Check if user is admin
	if userID != nil {
		user, err := h.userService.GetUserByID(userID.(string))
		if err == nil && user.IsAdmin() {
			isAdmin = true
		}
	}

	clientName := ""
	// If user_code is provided, try to get the client name
	if userCode != "" {
		name, err := h.deviceService.GetClientNameByUserCode(userCode)
		if err == nil {
			clientName = name
		}
	}

	templates.RenderTempl(c, http.StatusOK, templates.DevicePage(templates.DevicePageProps{
		BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: templates.NavbarProps{
			Username:   usernameStr,
			IsAdmin:    isAdmin,
			ActiveLink: "device",
		},
		Username:   usernameStr,
		UserCode:   userCode,
		ClientName: clientName,
		Error:      c.Query("error"),
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

	username := session.Get(SessionUsername)
	userCode := c.PostForm("user_code")

	usernameStr := ""
	if username != nil {
		usernameStr = username.(string)
	}

	// Check if user is admin for navbar
	isAdmin := false
	user, err := h.userService.GetUserByID(userID.(string))
	if err == nil && user.IsAdmin() {
		isAdmin = true
	}

	if userCode == "" {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.DevicePage(templates.DevicePageProps{
				BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: templates.NavbarProps{
					Username:   usernameStr,
					IsAdmin:    isAdmin,
					ActiveLink: "device",
				},
				Username: usernameStr,
				Error:    "Please enter a user code",
			}),
		)
		return
	}

	// Get client name before authorizing
	clientName, _ := h.deviceService.GetClientNameByUserCode(userCode)

	err = h.deviceService.AuthorizeDeviceCode(
		c.Request.Context(),
		userCode,
		userID.(string),
		usernameStr,
	)
	if err != nil {
		var errorMsg string
		switch {
		case errors.Is(err, services.ErrUserCodeNotFound):
			errorMsg = "User code not found"
		case errors.Is(err, services.ErrDeviceCodeExpired):
			errorMsg = "Code has expired, please request a new one"
		default:
			errorMsg = "Invalid or expired code"
		}

		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.DevicePage(templates.DevicePageProps{
				BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: templates.NavbarProps{
					Username:   usernameStr,
					IsAdmin:    isAdmin,
					ActiveLink: "device",
				},
				Username:   usernameStr,
				UserCode:   userCode,
				ClientName: clientName,
				Error:      errorMsg,
			}),
		)
		return
	}

	templates.RenderTempl(c, http.StatusOK, templates.SuccessPage(templates.SuccessPageProps{
		BaseProps:  templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		Username:   usernameStr,
		ClientName: clientName,
	}))
}
