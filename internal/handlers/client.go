package handlers

import (
	"net/http"
	"strings"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type ClientHandler struct {
	clientService        *services.ClientService
	authorizationService *services.AuthorizationService
}

func NewClientHandler(
	cs *services.ClientService,
	as *services.AuthorizationService,
) *ClientHandler {
	return &ClientHandler{clientService: cs, authorizationService: as}
}

// parseRedirectURIs parses a comma-separated string into a slice of trimmed URIs
func parseRedirectURIs(input string) []string {
	var redirectURIs []string
	if strings.TrimSpace(input) == "" {
		return redirectURIs
	}

	for uri := range strings.SplitSeq(input, ",") {
		if trimmed := strings.TrimSpace(uri); trimmed != "" {
			redirectURIs = append(redirectURIs, trimmed)
		}
	}
	return redirectURIs
}

// InjectPendingCount is a middleware that queries the pending client count for
// admin users and stores it in the gin context so buildNavbarProps can show the
// badge on every page. Non-admin users are skipped to avoid unnecessary queries.
func (h *ClientHandler) InjectPendingCount() gin.HandlerFunc {
	return func(c *gin.Context) {
		if u, exists := c.Get("user"); exists {
			if user, ok := u.(*models.User); ok && user.IsAdmin() {
				if count, err := h.clientService.CountPendingClients(
					c.Request.Context(),
				); err == nil {
					c.Set(ctxKeyPendingClientsCount, int(count))
				}
			}
		}
		c.Next()
	}
}

// ShowClientsPage displays the list of all OAuth clients
func (h *ClientHandler) ShowClientsPage(c *gin.Context) {
	params := parsePaginationParams(c)
	params.StatusFilter = c.Query("status")

	// Get paginated clients with creator information
	clients, pagination, err := h.clientService.ListClientsPaginatedWithCreator(params)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to load clients: "+err.Error())
		return
	}

	// Get flash messages from session
	session := sessions.Default(c)
	flashes := session.Flashes()
	if err := session.Save(); err != nil {
		// Log error but continue - flash message is not critical
		c.Set("session_save_error", err)
	}

	var successMsg string
	if len(flashes) > 0 {
		if msg, ok := flashes[0].(string); ok {
			successMsg = msg
		}
	}

	userModel := getUserFromContext(c)

	navbar := buildNavbarProps(c, userModel, "clients")

	templates.RenderTempl(c, http.StatusOK, templates.AdminClients(templates.ClientsPageProps{
		BaseProps:    templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps:  navbar,
		User:         userModel,
		Clients:      clients,
		Pagination:   pagination,
		Search:       params.Search,
		PageSize:     params.PageSize,
		Success:      successMsg,
		StatusFilter: params.StatusFilter,
	}))
}

// ShowCreateClientPage displays the form to create a new client
func (h *ClientHandler) ShowCreateClientPage(c *gin.Context) {
	userModel := getUserFromContext(c)

	templates.RenderTempl(c, http.StatusOK, templates.AdminClientForm(templates.ClientFormPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, userModel, "clients"),
		Title:       "Create OAuth Client",
		Method:      http.MethodPost,
		Action:      "/admin/clients",
		IsEdit:      false,
	}))
}

// CreateClient handles the creation of a new OAuth client
func (h *ClientHandler) CreateClient(c *gin.Context) {
	userID, _ := c.Get("user_id")

	req := services.CreateClientRequest{
		ClientName:                  c.PostForm("client_name"),
		Description:                 c.PostForm("description"),
		UserID:                      userID.(string),
		Scopes:                      c.PostForm("scopes"),
		RedirectURIs:                parseRedirectURIs(c.PostForm("redirect_uris")),
		CreatedBy:                   userID.(string),
		ClientType:                  core.NormalizeClientType(c.PostForm("client_type")),
		EnableDeviceFlow:            c.PostForm("enable_device_flow") == queryValueTrue,
		EnableAuthCodeFlow:          c.PostForm("enable_auth_code_flow") == queryValueTrue,
		EnableClientCredentialsFlow: c.PostForm("enable_client_credentials_flow") == queryValueTrue,
		IsAdminCreated:              true, // admin-created clients are immediately active
	}

	resp, err := h.clientService.CreateClient(c.Request.Context(), req)
	if err != nil {
		userModel := getUserFromContext(c)

		// Convert request data to ClientDisplay struct for template
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

		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.AdminClientForm(templates.ClientFormPageProps{
				BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: buildNavbarProps(c, userModel, "clients"),
				Client:      clientData,
				Error:       err.Error(),
				Title:       "Create OAuth Client",
				Method:      http.MethodPost,
				Action:      "/admin/clients",
				IsEdit:      false,
			}),
		)
		return
	}

	// Show the newly created client with the plain secret (only shown once)
	userModel := getUserFromContext(c)

	// Convert OAuthApplication to ClientDisplay for template
	clientDisplay := clientToDisplay(resp.OAuthApplication)

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminClientCreated(templates.ClientCreatedPageProps{
			BaseProps:    templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps:  buildNavbarProps(c, userModel, "clients"),
			Client:       clientDisplay,
			ClientSecret: resp.ClientSecretPlain,
		}),
	)
}

// ShowEditClientPage displays the form to edit an existing client
func (h *ClientHandler) ShowEditClientPage(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "Client not found")
		return
	}

	userModel := getUserFromContext(c)

	clientDisplay := clientToDisplay(client)

	templates.RenderTempl(c, http.StatusOK, templates.AdminClientForm(templates.ClientFormPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, userModel, "clients"),
		Client:      clientDisplay,
		Title:       "Edit OAuth Client",
		Method:      http.MethodPost,
		Action:      "/admin/clients/" + clientID,
		IsEdit:      true,
	}))
}

// UpdateClient handles updating an existing OAuth client
func (h *ClientHandler) UpdateClient(c *gin.Context) {
	clientID := c.Param("id")

	req := services.UpdateClientRequest{
		ClientName:                  c.PostForm("client_name"),
		Description:                 c.PostForm("description"),
		Scopes:                      c.PostForm("scopes"),
		RedirectURIs:                parseRedirectURIs(c.PostForm("redirect_uris")),
		Status:                      c.PostForm("status"),
		ClientType:                  core.NormalizeClientType(c.PostForm("client_type")),
		EnableDeviceFlow:            c.PostForm("enable_device_flow") == queryValueTrue,
		EnableAuthCodeFlow:          c.PostForm("enable_auth_code_flow") == queryValueTrue,
		EnableClientCredentialsFlow: c.PostForm("enable_client_credentials_flow") == queryValueTrue,
	}

	userID, _ := c.Get("user_id")
	err := h.clientService.UpdateClient(c.Request.Context(), clientID, userID.(string), req)
	if err != nil {
		client, _ := h.clientService.GetClient(clientID)

		userModel := getUserFromContext(c)

		// Convert form data to ClientDisplay for template
		clientDisplay := &templates.ClientDisplay{
			ID:                          client.ID,
			ClientID:                    client.ClientID,
			ClientName:                  req.ClientName,
			Description:                 req.Description,
			Scopes:                      req.Scopes,
			RedirectURIs:                strings.Join(req.RedirectURIs, ", "),
			ClientType:                  req.ClientType.String(),
			EnableDeviceFlow:            req.EnableDeviceFlow,
			EnableAuthCodeFlow:          req.EnableAuthCodeFlow,
			EnableClientCredentialsFlow: req.EnableClientCredentialsFlow,
			Status:                      req.Status,
			CreatedAt:                   client.CreatedAt,
			UpdatedAt:                   client.UpdatedAt,
		}

		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.AdminClientForm(templates.ClientFormPageProps{
				BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: buildNavbarProps(c, userModel, "clients"),
				Client:      clientDisplay,
				Error:       err.Error(),
				Title:       "Edit OAuth Client",
				Method:      http.MethodPost,
				Action:      "/admin/clients/" + clientID,
				IsEdit:      true,
			}),
		)
		return
	}

	c.Redirect(http.StatusFound, "/admin/clients/"+clientID+"?success=updated")
}

// DeleteClient handles deleting an OAuth client
func (h *ClientHandler) DeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	userID, _ := c.Get("user_id")
	err := h.clientService.DeleteClient(c.Request.Context(), clientID, userID.(string))
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to delete client: "+err.Error())
		return
	}

	// Store success message in session flash
	session := sessions.Default(c)
	session.AddFlash("Client deleted successfully")
	if err := session.Save(); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to save session: "+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/admin/clients")
}

// RegenerateSecret handles POST /admin/clients/:id/regenerate-secret to regenerate the client secret
func (h *ClientHandler) RegenerateSecret(c *gin.Context) {
	clientID := c.Param("id")

	userID, _ := c.Get("user_id")
	newSecret, err := h.clientService.RegenerateSecret(
		c.Request.Context(),
		clientID,
		userID.(string),
	)
	if err != nil {
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Failed to regenerate secret: "+err.Error(),
		)
		return
	}

	client, _ := h.clientService.GetClient(clientID)
	userModel := getUserFromContext(c)

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminClientSecret(templates.ClientSecretPageProps{
			BaseProps:    templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps:  buildNavbarProps(c, userModel, "clients"),
			Client:       client,
			ClientSecret: newSecret,
		}),
	)
}

// ViewClient displays detailed information about a client
func (h *ClientHandler) ViewClient(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "Client not found")
		return
	}

	activeTokenCount, _ := h.clientService.CountActiveTokens(clientID)

	userModel := getUserFromContext(c)

	// Map query-param success codes to human-readable messages
	successMsg := ""
	switch c.Query("success") {
	case "tokens_revoked":
		successMsg = "All active tokens have been revoked. Users will need to re-authenticate."
	case "updated":
		successMsg = "Client updated successfully."
	case "approved":
		successMsg = "Client approved. It is now active and can be used for OAuth flows."
	case "rejected":
		successMsg = "Client rejected. It has been set to inactive."
	}

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminClientDetail(templates.ClientDetailPageProps{
			BaseProps:        templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps:      buildNavbarProps(c, userModel, "clients"),
			Client:           client,
			ActiveTokenCount: activeTokenCount,
			Success:          successMsg,
		}),
	)
}

// ApproveClient sets a pending client's status to active.
func (h *ClientHandler) ApproveClient(c *gin.Context) {
	clientID := c.Param("id")
	userID, _ := c.Get("user_id")

	if err := h.clientService.ApproveClient(
		c.Request.Context(),
		clientID,
		userID.(string),
	); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to approve client: "+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/admin/clients/"+clientID+"?success=approved")
}

// RejectClient sets a pending client's status to inactive.
func (h *ClientHandler) RejectClient(c *gin.Context) {
	clientID := c.Param("id")
	userID, _ := c.Get("user_id")

	if err := h.clientService.RejectClient(
		c.Request.Context(),
		clientID,
		userID.(string),
	); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to reject client: "+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/admin/clients/"+clientID+"?success=rejected")
}

// ListClientAuthorizations shows all users who have granted access to this client (admin overview).
func (h *ClientHandler) ListClientAuthorizations(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "Client not found")
		return
	}

	auths, err := h.authorizationService.ListClientAuthorizations(c.Request.Context(), clientID)
	if err != nil {
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Failed to load authorizations: "+err.Error(),
		)
		return
	}

	displayAuths := make([]templates.ClientAuthorizationDisplay, 0, len(auths))
	for _, a := range auths {
		displayAuths = append(displayAuths, templates.ClientAuthorizationDisplay{
			UUID:      a.UUID,
			UserID:    a.UserID,
			Username:  a.Username,
			Email:     a.Email,
			Scopes:    a.Scopes,
			GrantedAt: a.GrantedAt,
		})
	}

	userModel := getUserFromContext(c)

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminClientAuthorizations(templates.ClientAuthorizationsPageProps{
			BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps:    buildNavbarProps(c, userModel, "clients"),
			Client:         client,
			Authorizations: displayAuths,
		}),
	)
}

// RevokeAllTokens revokes all active tokens for a client (admin danger zone action).
func (h *ClientHandler) RevokeAllTokens(c *gin.Context) {
	clientID := c.Param("id")
	userID, _ := c.Get("user_id")

	revokedCount, err := h.authorizationService.RevokeAllApplicationTokens(
		c.Request.Context(),
		clientID,
		userID.(string),
	)
	if err != nil {
		userModel := getUserFromContext(c)
		client, _ := h.clientService.GetClient(clientID)
		activeTokenCount, _ := h.clientService.CountActiveTokens(clientID)

		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.AdminClientDetail(templates.ClientDetailPageProps{
				BaseProps:        templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps:      buildNavbarProps(c, userModel, "clients"),
				Client:           client,
				ActiveTokenCount: activeTokenCount,
				Error:            "Failed to revoke tokens: " + err.Error(),
			}),
		)
		return
	}

	_ = revokedCount
	c.Redirect(http.StatusFound, "/admin/clients/"+clientID+"?success=tokens_revoked")
}
