package handlers

import (
	"net/http"

	"github.com/appleboy/authgate/internal/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type ClientHandler struct {
	clientService *services.ClientService
}

func NewClientHandler(cs *services.ClientService) *ClientHandler {
	return &ClientHandler{clientService: cs}
}

// ShowClientsPage displays the list of all OAuth clients
func (h *ClientHandler) ShowClientsPage(c *gin.Context) {
	clients, err := h.clientService.ListClients()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load clients: " + err.Error(),
		})
		return
	}

	// Get flash messages from session
	session := sessions.Default(c)
	flashes := session.Flashes()
	session.Save()

	var successMsg string
	if len(flashes) > 0 {
		if msg, ok := flashes[0].(string); ok {
			successMsg = msg
		}
	}

	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/clients.html", gin.H{
		"clients": clients,
		"user":    user,
		"success": successMsg,
	})
}

// ShowCreateClientPage displays the form to create a new client
func (h *ClientHandler) ShowCreateClientPage(c *gin.Context) {
	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_form.html", gin.H{
		"user":   user,
		"action": "/admin/clients",
		"method": "POST",
		"title":  "Create OAuth Client",
	})
}

// CreateClient handles the creation of a new OAuth client
func (h *ClientHandler) CreateClient(c *gin.Context) {
	userID, _ := c.Get("user_id")

	req := services.CreateClientRequest{
		ClientName:   c.PostForm("client_name"),
		Description:  c.PostForm("description"),
		Scopes:       c.PostForm("scopes"),
		GrantTypes:   c.PostForm("grant_types"),
		RedirectURIs: c.PostForm("redirect_uris"),
		CreatedBy:    userID.(string),
	}

	resp, err := h.clientService.CreateClient(req)
	if err != nil {
		user, _ := c.Get("user")
		c.HTML(http.StatusBadRequest, "admin/client_form.html", gin.H{
			"user":   user,
			"error":  err.Error(),
			"action": "/admin/clients",
			"method": "POST",
			"title":  "Create OAuth Client",
			"client": map[string]string{
				"client_name":   req.ClientName,
				"description":   req.Description,
				"scopes":        req.Scopes,
				"grant_types":   req.GrantTypes,
				"redirect_uris": req.RedirectURIs,
			},
		})
		return
	}

	// Show the newly created client with the plain secret (only shown once)
	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_created.html", gin.H{
		"user":          user,
		"client":        resp.OAuthClient,
		"client_secret": resp.ClientSecretPlain,
	})
}

// ShowEditClientPage displays the form to edit an existing client
func (h *ClientHandler) ShowEditClientPage(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Client not found",
		})
		return
	}

	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_form.html", gin.H{
		"user":   user,
		"client": client,
		"action": "/admin/clients/" + clientID,
		"method": "POST",
		"title":  "Edit OAuth Client",
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
		RedirectURIs: c.PostForm("redirect_uris"),
		IsActive:     c.PostForm("is_active") == "true",
	}

	err := h.clientService.UpdateClient(clientID, req)
	if err != nil {
		client, _ := h.clientService.GetClient(clientID)
		user, _ := c.Get("user")
		c.HTML(http.StatusBadRequest, "admin/client_form.html", gin.H{
			"user":   user,
			"error":  err.Error(),
			"client": client,
			"action": "/admin/clients/" + clientID,
			"method": "POST",
			"title":  "Edit OAuth Client",
		})
		return
	}

	// Store success message in session flash
	session := sessions.Default(c)
	session.AddFlash("Client updated successfully")
	session.Save()

	c.Redirect(http.StatusFound, "/admin/clients")
}

// DeleteClient handles deleting an OAuth client
func (h *ClientHandler) DeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	err := h.clientService.DeleteClient(clientID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to delete client: " + err.Error(),
		})
		return
	}

	// Store success message in session flash
	session := sessions.Default(c)
	session.AddFlash("Client deleted successfully")
	session.Save()

	c.Redirect(http.StatusFound, "/admin/clients")
}

// RegenerateSecret handles regenerating the client secret
func (h *ClientHandler) RegenerateSecret(c *gin.Context) {
	clientID := c.Param("id")

	newSecret, err := h.clientService.RegenerateSecret(clientID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to regenerate secret: " + err.Error(),
		})
		return
	}

	client, _ := h.clientService.GetClient(clientID)
	user, _ := c.Get("user")

	c.HTML(http.StatusOK, "admin/client_secret.html", gin.H{
		"user":          user,
		"client":        client,
		"client_secret": newSecret,
	})
}

// ViewClient displays detailed information about a client
func (h *ClientHandler) ViewClient(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Client not found",
		})
		return
	}

	user, _ := c.Get("user")
	c.HTML(http.StatusOK, "admin/client_detail.html", gin.H{
		"user":   user,
		"client": client,
	})
}
