package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/appleboy/authgate/internal/middleware"
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
	c.HTML(http.StatusOK, "admin/clients.html", gin.H{
		"clients":    clients,
		"Pagination": pagination,
		"Search":     search,
		"PageSize":   pageSize,
		"user":       user,
		"success":    successMsg,
		"csrf_token": middleware.GetCSRFToken(c),
	})
}

// ShowCreateClientPage displays the form to create a new client
func (h *ClientHandler) ShowCreateClientPage(c *gin.Context) {
	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_form.html", gin.H{
		"user":       user,
		"action":     "/admin/clients",
		"method":     "POST",
		"title":      "Create OAuth Client",
		"csrf_token": middleware.GetCSRFToken(c),
	})
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
		c.HTML(http.StatusBadRequest, "admin/client_form.html", gin.H{
			"user":       user,
			"error":      err.Error(),
			"action":     "/admin/clients",
			"method":     "POST",
			"title":      "Create OAuth Client",
			"csrf_token": middleware.GetCSRFToken(c),
			"client": map[string]string{
				"client_name":   req.ClientName,
				"description":   req.Description,
				"scopes":        req.Scopes,
				"grant_types":   req.GrantTypes,
				"redirect_uris": strings.Join(req.RedirectURIs, ", "),
			},
		})
		return
	}

	// Show the newly created client with the plain secret (only shown once)
	// Prepare client data for template
	clientData := gin.H{
		"ID":               resp.ID,
		"ClientID":         resp.ClientID,
		"ClientName":       resp.ClientName,
		"Description":      resp.Description,
		"Scopes":           resp.Scopes,
		"GrantTypes":       resp.GrantTypes,
		"RedirectURIs":     resp.RedirectURIs.Join(", "),
		"EnableDeviceFlow": resp.EnableDeviceFlow,
		"IsActive":         resp.IsActive,
	}

	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_created.html", gin.H{
		"user":          user,
		"client":        clientData,
		"client_secret": resp.ClientSecretPlain,
		"csrf_token":    middleware.GetCSRFToken(c),
	})
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

	// Prepare client data for template
	clientData := gin.H{
		"ID":               client.ID,
		"ClientID":         client.ClientID,
		"ClientName":       client.ClientName,
		"Description":      client.Description,
		"Scopes":           client.Scopes,
		"GrantTypes":       client.GrantTypes,
		"RedirectURIs":     client.RedirectURIs.Join(", "),
		"EnableDeviceFlow": client.EnableDeviceFlow,
		"IsActive":         client.IsActive,
		"CreatedAt":        client.CreatedAt,
		"UpdatedAt":        client.UpdatedAt,
	}

	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_form.html", gin.H{
		"user":       user,
		"client":     clientData,
		"action":     "/admin/clients/" + clientID,
		"method":     "POST",
		"title":      "Edit OAuth Client",
		"csrf_token": middleware.GetCSRFToken(c),
	})
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

		// Prepare client data for template
		clientData := gin.H{
			"ID":               client.ID,
			"ClientID":         client.ClientID,
			"ClientName":       req.ClientName,
			"Description":      req.Description,
			"Scopes":           req.Scopes,
			"GrantTypes":       req.GrantTypes,
			"RedirectURIs":     strings.Join(req.RedirectURIs, ", "),
			"EnableDeviceFlow": client.EnableDeviceFlow,
			"IsActive":         req.IsActive,
		}

		user, _ := c.Get("user")
		c.HTML(http.StatusBadRequest, "admin/client_form.html", gin.H{
			"user":       user,
			"error":      err.Error(),
			"client":     clientData,
			"action":     "/admin/clients/" + clientID,
			"method":     "POST",
			"title":      "Edit OAuth Client",
			"csrf_token": middleware.GetCSRFToken(c),
		})
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

	c.HTML(http.StatusOK, "admin/client_secret.html", gin.H{
		"user":          user,
		"client":        client,
		"client_secret": newSecret,
		"csrf_token":    middleware.GetCSRFToken(c),
	})
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

	// Prepare client data for template
	clientData := gin.H{
		"ID":               client.ID,
		"ClientID":         client.ClientID,
		"ClientName":       client.ClientName,
		"Description":      client.Description,
		"Scopes":           client.Scopes,
		"GrantTypes":       client.GrantTypes,
		"RedirectURIs":     client.RedirectURIs.Join(", "),
		"EnableDeviceFlow": client.EnableDeviceFlow,
		"IsActive":         client.IsActive,
		"CreatedAt":        client.CreatedAt,
		"UpdatedAt":        client.UpdatedAt,
	}

	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_detail.html", gin.H{
		"user":       user,
		"client":     clientData,
		"csrf_token": middleware.GetCSRFToken(c),
	})
}
