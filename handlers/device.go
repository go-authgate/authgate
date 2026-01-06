package handlers

import (
	"net/http"

	"github.com/appleboy/authgate/config"
	"github.com/appleboy/authgate/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type DeviceHandler struct {
	deviceService *services.DeviceService
	config        *config.Config
}

func NewDeviceHandler(ds *services.DeviceService, cfg *config.Config) *DeviceHandler {
	return &DeviceHandler{deviceService: ds, config: cfg}
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

	dc, err := h.deviceService.GenerateDeviceCode(clientID, scope)
	if err != nil {
		if err == services.ErrInvalidClient {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Unknown client_id",
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
		"device_code":               dc.DeviceCode,
		"user_code":                 services.FormatUserCode(dc.UserCode),
		"verification_uri":          h.config.BaseURL + "/device",
		"verification_uri_complete": h.config.BaseURL + "/device?user_code=" + services.FormatUserCode(dc.UserCode),
		"expires_in":                int(h.config.DeviceCodeExpiration.Seconds()),
		"interval":                  dc.Interval,
	})
}

// DevicePage renders the device code input page
func (h *DeviceHandler) DevicePage(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get(SessionUsername)
	userCode := c.Query("user_code")

	c.HTML(http.StatusOK, "device.html", gin.H{
		"username":  username,
		"user_code": userCode,
		"error":     c.Query("error"),
	})
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
	if userCode == "" {
		c.HTML(http.StatusBadRequest, "device.html", gin.H{
			"username": session.Get(SessionUsername),
			"error":    "Please enter a user code",
		})
		return
	}

	err := h.deviceService.AuthorizeDeviceCode(userCode, userID.(string))
	if err != nil {
		errorMsg := "Invalid or expired code"
		if err == services.ErrUserCodeNotFound {
			errorMsg = "User code not found"
		} else if err == services.ErrDeviceCodeExpired {
			errorMsg = "Code has expired, please request a new one"
		}

		c.HTML(http.StatusBadRequest, "device.html", gin.H{
			"username":  session.Get(SessionUsername),
			"user_code": userCode,
			"error":     errorMsg,
		})
		return
	}

	c.HTML(http.StatusOK, "success.html", gin.H{
		"username": session.Get(SessionUsername),
	})
}
