package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/appleboy/authgate/internal/middleware"
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/templates"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type ClientHandler struct {
	clientService *services.ClientService
}

func NewClientHandler(cs *services.ClientService) *ClientHandler {
	return &ClientHandler{clientService: cs}
}

// parseRedirectURIs parses a comma-separated string into a slice of trimmed URIs
func parseRedirectURIs(input string) []string {
	var redirectURIs []string
	if strings.TrimSpace(input) == "" {
		return redirectURIs
	}

	parts := strings.Split(input, ",")
	for _, uri := range parts {
		if trimmed := strings.TrimSpace(uri); trimmed != "" {
			redirectURIs = append(redirectURIs, trimmed)
		}
	}
	return redirectURIs
}

// ShowClientsPage displays the list of all OAuth clients
func (h *ClientHandler) ShowClientsPage(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	search := c.Query("search")

	// Create pagination params
	params := store.NewPaginationParams(page, pageSize, search)

	// Get paginated clients with creator information
	clients, pagination, err := h.clientService.ListClientsPaginatedWithCreator(params)
	if err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Failed to load clients: " + err.Error(),
			}),
		)
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

	user, _ := c.Get("user")
	userModel := user.(*models.User)

	templates.RenderTempl(c, http.StatusOK, templates.AdminClients(templates.ClientsPageProps{
		BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: templates.NavbarProps{
			Username:   userModel.Username,
			IsAdmin:    userModel.IsAdmin(),
			ActiveLink: "clients",
		},
		User:       userModel,
		Clients:    clients,
		Pagination: pagination,
		Search:     search,
		PageSize:   pageSize,
		Success:    successMsg,
	}))
}

// ShowCreateClientPage displays the form to create a new client
func (h *ClientHandler) ShowCreateClientPage(c *gin.Context) {
	user, _ := c.Get("user")
	userModel := user.(*models.User)

	templates.RenderTempl(c, http.StatusOK, templates.AdminClientForm(templates.ClientFormPageProps{
		BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: templates.NavbarProps{
			Username:   userModel.Username,
			IsAdmin:    userModel.IsAdmin(),
			ActiveLink: "clients",
		},
		Title:  "Create OAuth Client",
		Method: "POST",
		Action: "/admin/clients",
		IsEdit: false,
	}))
}

// CreateClient handles the creation of a new OAuth client
func (h *ClientHandler) CreateClient(c *gin.Context) {
	userID, _ := c.Get("user_id")

	req := services.CreateClientRequest{
		ClientName:   c.PostForm("client_name"),
		Description:  c.PostForm("description"),
		UserID:       userID.(string),
		Scopes:       c.PostForm("scopes"),
		GrantTypes:   c.PostForm("grant_types"),
		RedirectURIs: parseRedirectURIs(c.PostForm("redirect_uris")),
		CreatedBy:    userID.(string),
	}

	resp, err := h.clientService.CreateClient(c.Request.Context(), req)
	if err != nil {
		user, _ := c.Get("user")
		userModel := user.(*models.User)

		// Convert request data to ClientDisplay struct for template
		clientData := &templates.ClientDisplay{
			ClientName:   req.ClientName,
			Description:  req.Description,
			Scopes:       req.Scopes,
			GrantTypes:   req.GrantTypes,
			RedirectURIs: strings.Join(req.RedirectURIs, ", "),
		}

		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.AdminClientForm(templates.ClientFormPageProps{
				BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: templates.NavbarProps{
					Username:   userModel.Username,
					IsAdmin:    userModel.IsAdmin(),
					ActiveLink: "clients",
				},
				Client: clientData,
				Error:  err.Error(),
				Title:  "Create OAuth Client",
				Method: "POST",
				Action: "/admin/clients",
				IsEdit: false,
			}),
		)
		return
	}

	// Show the newly created client with the plain secret (only shown once)
	user, _ := c.Get("user")
	userModel := user.(*models.User)

	// Convert OAuthApplication to ClientDisplay for template
	clientDisplay := &templates.ClientDisplay{
		ID:               resp.ID,
		ClientID:         resp.ClientID,
		ClientName:       resp.ClientName,
		Description:      resp.Description,
		Scopes:           resp.Scopes,
		GrantTypes:       resp.GrantTypes,
		RedirectURIs:     resp.RedirectURIs.Join(", "),
		EnableDeviceFlow: resp.EnableDeviceFlow,
		IsActive:         resp.IsActive,
	}

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminClientCreated(templates.ClientCreatedPageProps{
			BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: templates.NavbarProps{
				Username:   userModel.Username,
				IsAdmin:    userModel.IsAdmin(),
				ActiveLink: "clients",
			},
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
		templates.RenderTempl(c, http.StatusNotFound, templates.ErrorPage(templates.ErrorPageProps{
			Error: "Client not found",
		}))
		return
	}

	user, _ := c.Get("user")
	userModel := user.(*models.User)

	// Convert OAuthApplication to ClientDisplay for template
	clientDisplay := &templates.ClientDisplay{
		ID:               client.ID,
		ClientID:         client.ClientID,
		ClientName:       client.ClientName,
		Description:      client.Description,
		Scopes:           client.Scopes,
		GrantTypes:       client.GrantTypes,
		RedirectURIs:     client.RedirectURIs.Join(", "),
		EnableDeviceFlow: client.EnableDeviceFlow,
		IsActive:         client.IsActive,
		CreatedAt:        client.CreatedAt,
		UpdatedAt:        client.UpdatedAt,
	}

	templates.RenderTempl(c, http.StatusOK, templates.AdminClientForm(templates.ClientFormPageProps{
		BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: templates.NavbarProps{
			Username:   userModel.Username,
			IsAdmin:    userModel.IsAdmin(),
			ActiveLink: "clients",
		},
		Client: clientDisplay,
		Title:  "Edit OAuth Client",
		Method: "POST",
		Action: "/admin/clients/" + clientID,
		IsEdit: true,
	}))
}

// UpdateClient handles updating an existing OAuth client
func (h *ClientHandler) UpdateClient(c *gin.Context) {
	clientID := c.Param("id")

	req := services.UpdateClientRequest{
		ClientName:   c.PostForm("client_name"),
		Description:  c.PostForm("description"),
		Scopes:       c.PostForm("scopes"),
		GrantTypes:   c.PostForm("grant_types"),
		RedirectURIs: parseRedirectURIs(c.PostForm("redirect_uris")),
		IsActive:     c.PostForm("is_active") == "true",
	}

	userID, _ := c.Get("user_id")
	err := h.clientService.UpdateClient(c.Request.Context(), clientID, userID.(string), req)
	if err != nil {
		client, _ := h.clientService.GetClient(clientID)

		user, _ := c.Get("user")
		userModel := user.(*models.User)

		// Convert form data to ClientDisplay for template
		clientDisplay := &templates.ClientDisplay{
			ID:               client.ID,
			ClientID:         client.ClientID,
			ClientName:       req.ClientName,
			Description:      req.Description,
			Scopes:           req.Scopes,
			GrantTypes:       req.GrantTypes,
			RedirectURIs:     strings.Join(req.RedirectURIs, ", "),
			EnableDeviceFlow: client.EnableDeviceFlow,
			IsActive:         req.IsActive,
			CreatedAt:        client.CreatedAt,
			UpdatedAt:        client.UpdatedAt,
		}

		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.AdminClientForm(templates.ClientFormPageProps{
				BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: templates.NavbarProps{
					Username:   userModel.Username,
					IsAdmin:    userModel.IsAdmin(),
					ActiveLink: "clients",
				},
				Client: clientDisplay,
				Error:  err.Error(),
				Title:  "Edit OAuth Client",
				Method: "POST",
				Action: "/admin/clients/" + clientID,
				IsEdit: true,
			}),
		)
		return
	}

	// Store success message in session flash
	session := sessions.Default(c)
	session.AddFlash("Client updated successfully")
	if err := session.Save(); err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Failed to save session: " + err.Error(),
			}),
		)
		return
	}

	c.Redirect(http.StatusFound, "/admin/clients")
}

// DeleteClient handles deleting an OAuth client
func (h *ClientHandler) DeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	userID, _ := c.Get("user_id")
	err := h.clientService.DeleteClient(c.Request.Context(), clientID, userID.(string))
	if err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Failed to delete client: " + err.Error(),
			}),
		)
		return
	}

	// Store success message in session flash
	session := sessions.Default(c)
	session.AddFlash("Client deleted successfully")
	if err := session.Save(); err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Failed to save session: " + err.Error(),
			}),
		)
		return
	}

	c.Redirect(http.StatusFound, "/admin/clients")
}

// RegenerateSecret handles regenerating the client secret
func (h *ClientHandler) RegenerateSecret(c *gin.Context) {
	clientID := c.Param("id")

	userID, _ := c.Get("user_id")
	newSecret, err := h.clientService.RegenerateSecret(
		c.Request.Context(),
		clientID,
		userID.(string),
	)
	if err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Failed to regenerate secret: " + err.Error(),
			}),
		)
		return
	}

	client, _ := h.clientService.GetClient(clientID)
	user, _ := c.Get("user")
	userModel := user.(*models.User)

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminClientSecret(templates.ClientSecretPageProps{
			BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: templates.NavbarProps{
				Username:   userModel.Username,
				IsAdmin:    userModel.IsAdmin(),
				ActiveLink: "clients",
			},
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
		templates.RenderTempl(c, http.StatusNotFound, templates.ErrorPage(templates.ErrorPageProps{
			Error: "Client not found",
		}))
		return
	}

	user, _ := c.Get("user")
	userModel := user.(*models.User)

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminClientDetail(templates.ClientDetailPageProps{
			BaseProps: templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: templates.NavbarProps{
				Username:   userModel.Username,
				IsAdmin:    userModel.IsAdmin(),
				ActiveLink: "clients",
			},
			Client: client,
		}),
	)
}
