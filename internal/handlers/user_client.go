package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

// UserClientHandler handles the /apps area for authenticated (non-admin) users
// to register and manage their own OAuth applications.
type UserClientHandler struct {
	clientService *services.ClientService
}

func NewUserClientHandler(cs *services.ClientService) *UserClientHandler {
	return &UserClientHandler{clientService: cs}
}

// ShowMyAppsPage lists all OAuth applications owned by the logged-in user.
func (h *UserClientHandler) ShowMyAppsPage(c *gin.Context) {
	userID := getUserIDFromContext(c)
	userModel := getUserFromContext(c)

	params := parsePaginationParams(c)
	apps, pagination, err := h.clientService.ListClientsByUser(userID, params)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to load apps: "+err.Error())
		return
	}

	templates.RenderTempl(c, http.StatusOK, templates.MyApps(templates.MyAppsPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, userModel, "my-apps"),
		Apps:        apps,
		Pagination:  pagination,
		PageSize:    params.PageSize,
		Search:      params.Search,
	}))
}

// ShowCreateAppPage displays the form to register a new application.
func (h *UserClientHandler) ShowCreateAppPage(c *gin.Context) {
	userModel := getUserFromContext(c)

	templates.RenderTempl(c, http.StatusOK, templates.UserAppForm(templates.UserClientFormPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, userModel, "my-apps"),
		Title:       "Register New App",
		Method:      http.MethodPost,
		Action:      "/apps",
		IsEdit:      false,
	}))
}

// CreateApp handles POST /apps to register a new OAuth client.
func (h *UserClientHandler) CreateApp(c *gin.Context) {
	userID := getUserIDFromContext(c)
	if userID == "" {
		renderErrorPage(c, http.StatusUnauthorized, "User not authenticated")
		return
	}
	userModel := getUserFromContext(c)

	req := services.CreateClientRequest{
		ClientName:                  c.PostForm("client_name"),
		Description:                 c.PostForm("description"),
		UserID:                      userID,
		Scopes:                      c.PostForm("scopes"),
		RedirectURIs:                parseRedirectURIs(c.PostForm("redirect_uris")),
		CreatedBy:                   userID,
		ClientType:                  core.NormalizeClientType(c.PostForm("client_type")),
		EnableDeviceFlow:            c.PostForm("enable_device_flow") == queryValueTrue,
		EnableAuthCodeFlow:          c.PostForm("enable_auth_code_flow") == queryValueTrue,
		EnableClientCredentialsFlow: c.PostForm("enable_client_credentials_flow") == queryValueTrue,
		IsAdminCreated:              false, // user-created: starts as pending
	}

	// Validate scopes before calling service to give a user-friendly error
	if req.Scopes != "" {
		for scope := range strings.FieldsSeq(req.Scopes) {
			switch scope {
			case "email", "profile", "openid", "offline_access":
				// ok
			default:
				renderUserAppForm(
					c,
					userModel,
					nil,
					"/apps",
					false,
					"Invalid scope: "+scope+". Allowed scopes are: email, profile, openid, offline_access",
				)
				return
			}
		}
	}

	resp, err := h.clientService.CreateClient(c.Request.Context(), req)
	if err != nil {
		clientData := &templates.ClientDisplay{
			ClientName:                  req.ClientName,
			Description:                 req.Description,
			Scopes:                      req.Scopes,
			RedirectURIs:                strings.Join(req.RedirectURIs, ", "),
			ClientType:                  req.ClientType.String(),
			EnableDeviceFlow:            req.EnableDeviceFlow,
			EnableAuthCodeFlow:          req.EnableAuthCodeFlow,
			EnableClientCredentialsFlow: req.EnableClientCredentialsFlow,
		}
		renderUserAppForm(c, userModel, clientData, "/apps", false, err.Error())
		return
	}

	clientDisplay := clientToDisplay(resp.OAuthApplication)

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.UserAppCreated(templates.UserClientCreatedPageProps{
			BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: buildNavbarProps(c, userModel, "my-apps"),
			Client:      clientDisplay,
			PlainSecret: resp.ClientSecretPlain,
		}),
	)
}

// ShowAppPage displays details for a user-owned app.
func (h *UserClientHandler) ShowAppPage(c *gin.Context) {
	clientID := c.Param("id")
	userID := getUserIDFromContext(c)
	userModel := getUserFromContext(c)

	client, err := h.clientService.GetClient(c.Request.Context(), clientID)
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "App not found")
		return
	}

	if client.UserID != userID {
		renderErrorPage(c, http.StatusForbidden, "You do not have access to this app")
		return
	}

	activeTokens, _ := h.clientService.CountActiveTokens(clientID)

	successMsg := ""
	if c.Query("success") == "updated" {
		successMsg = "App updated successfully."
	}

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.UserAppDetail(templates.UserClientDetailPageProps{
			BaseProps:    templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps:  buildNavbarProps(c, userModel, "my-apps"),
			Client:       clientToDisplay(client),
			ActiveTokens: activeTokens,
			Success:      successMsg,
		}),
	)
}

// ShowEditAppPage displays the edit form for a user-owned app.
func (h *UserClientHandler) ShowEditAppPage(c *gin.Context) {
	clientID := c.Param("id")
	userID := getUserIDFromContext(c)
	userModel := getUserFromContext(c)

	client, err := h.clientService.GetClient(c.Request.Context(), clientID)
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "App not found")
		return
	}

	if client.UserID != userID {
		renderErrorPage(c, http.StatusForbidden, "You do not have access to this app")
		return
	}

	action := "/apps/" + clientID
	templates.RenderTempl(c, http.StatusOK, templates.UserAppForm(templates.UserClientFormPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, userModel, "my-apps"),
		Title:       "Edit App",
		Method:      http.MethodPost,
		Action:      action,
		IsEdit:      true,
		Client:      clientToDisplay(client),
	}))
}

// UpdateApp handles POST /apps/:id to update a user-owned app.
func (h *UserClientHandler) UpdateApp(c *gin.Context) {
	clientID := c.Param("id")
	userID := getUserIDFromContext(c)
	userModel := getUserFromContext(c)

	req := services.UserUpdateClientRequest{
		ClientName:                  c.PostForm("client_name"),
		Description:                 c.PostForm("description"),
		Scopes:                      c.PostForm("scopes"),
		RedirectURIs:                parseRedirectURIs(c.PostForm("redirect_uris")),
		ClientType:                  core.NormalizeClientType(c.PostForm("client_type")),
		EnableDeviceFlow:            c.PostForm("enable_device_flow") == queryValueTrue,
		EnableAuthCodeFlow:          c.PostForm("enable_auth_code_flow") == queryValueTrue,
		EnableClientCredentialsFlow: c.PostForm("enable_client_credentials_flow") == queryValueTrue,
	}

	err := h.clientService.UserUpdateClient(c.Request.Context(), clientID, userID, req)
	if err != nil {
		if errors.Is(err, services.ErrClientOwnershipRequired) {
			renderErrorPage(c, http.StatusForbidden, err.Error())
			return
		}

		client, _ := h.clientService.GetClient(c.Request.Context(), clientID)
		clientData := &templates.ClientDisplay{
			ClientName:                  req.ClientName,
			Description:                 req.Description,
			Scopes:                      req.Scopes,
			RedirectURIs:                strings.Join(req.RedirectURIs, ", "),
			ClientType:                  req.ClientType.String(),
			EnableDeviceFlow:            req.EnableDeviceFlow,
			EnableAuthCodeFlow:          req.EnableAuthCodeFlow,
			EnableClientCredentialsFlow: req.EnableClientCredentialsFlow,
		}
		if client != nil {
			clientData.ID = client.ID
			clientData.ClientID = client.ClientID
			clientData.Status = client.Status
		}
		renderUserAppForm(c, userModel, clientData, "/apps/"+clientID, true, err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/apps/"+clientID+"?success=updated")
}

// DeleteApp handles POST /apps/:id/delete to remove a pending or inactive user-owned app.
func (h *UserClientHandler) DeleteApp(c *gin.Context) {
	clientID := c.Param("id")
	userID := getUserIDFromContext(c)

	err := h.clientService.UserDeleteClient(c.Request.Context(), clientID, userID)
	if err != nil {
		if errors.Is(err, services.ErrClientOwnershipRequired) {
			renderErrorPage(c, http.StatusForbidden, err.Error())
			return
		}
		if errors.Is(err, services.ErrCannotDeleteActiveClient) {
			renderErrorPage(c, http.StatusBadRequest, err.Error())
			return
		}
		renderErrorPage(c, http.StatusInternalServerError, "Failed to delete app: "+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/apps")
}

// RegenerateAppSecret handles POST /apps/:id/regenerate-secret.
func (h *UserClientHandler) RegenerateAppSecret(c *gin.Context) {
	clientID := c.Param("id")
	userID := getUserIDFromContext(c)
	userModel := getUserFromContext(c)

	// Ownership check
	client, err := h.clientService.GetClient(c.Request.Context(), clientID)
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "App not found")
		return
	}
	if client.UserID != userID {
		renderErrorPage(c, http.StatusForbidden, "You do not have access to this app")
		return
	}

	newSecret, err := h.clientService.RegenerateSecret(
		c.Request.Context(),
		clientID,
		userID,
	)
	if err != nil {
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Failed to regenerate secret: "+err.Error(),
		)
		return
	}

	display := clientToDisplay(client)

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.UserAppSecret(templates.UserClientSecretPageProps{
			BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: buildNavbarProps(c, userModel, "my-apps"),
			Client:      display,
			PlainSecret: newSecret,
		}),
	)
}

func renderUserAppForm(
	c *gin.Context,
	user *models.User,
	client *templates.ClientDisplay,
	action string,
	isEdit bool,
	errMsg string,
) {
	title := "Register New App"
	if isEdit {
		title = "Edit App"
	}
	templates.RenderTempl(
		c,
		http.StatusBadRequest,
		templates.UserAppForm(templates.UserClientFormPageProps{
			BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: buildNavbarProps(c, user, "my-apps"),
			Title:       title,
			Method:      http.MethodPost,
			Action:      action,
			IsEdit:      isEdit,
			Client:      client,
			Error:       errMsg,
		}),
	)
}
