package handlers

import (
	"strconv"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

// parsePaginationParams extracts page, page_size, and search query params.
func parsePaginationParams(c *gin.Context) store.PaginationParams {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	search := c.Query("search")
	return store.NewPaginationParams(page, pageSize, search)
}

// respondOAuthError writes an RFC-compliant OAuth error JSON response.
func respondOAuthError(c *gin.Context, status int, errorCode, description string) {
	resp := gin.H{"error": errorCode}
	if description != "" {
		resp["error_description"] = description
	}
	c.JSON(status, resp)
}

// getUserFromContext returns the *models.User stored by RequireAuth middleware,
// or nil if no user is present.
func getUserFromContext(c *gin.Context) *models.User {
	if u, exists := c.Get("user"); exists {
		if user, ok := u.(*models.User); ok {
			return user
		}
	}
	return nil
}

// clientToDisplay converts an OAuthApplication model to a ClientDisplay template struct.
func clientToDisplay(app *models.OAuthApplication) *templates.ClientDisplay {
	if app == nil {
		return nil
	}
	return &templates.ClientDisplay{
		ID:                          app.ID,
		ClientID:                    app.ClientID,
		ClientName:                  app.ClientName,
		Description:                 app.Description,
		UserID:                      app.UserID,
		Scopes:                      app.Scopes,
		GrantTypes:                  app.GrantTypes,
		RedirectURIs:                app.RedirectURIs.Join(", "),
		ClientType:                  app.ClientType,
		EnableDeviceFlow:            app.EnableDeviceFlow,
		EnableAuthCodeFlow:          app.EnableAuthCodeFlow,
		EnableClientCredentialsFlow: app.EnableClientCredentialsFlow,
		Status:                      app.Status,
		CreatedAt:                   app.CreatedAt,
		UpdatedAt:                   app.UpdatedAt,
	}
}

const (
	ctxKeyPendingClientsCount = "pending_clients_count"
	// queryValueTrue represents the string "true" used in query parameters.
	queryValueTrue = "true"
)

// buildNavbarProps creates NavbarProps from a user model and active link identifier.
// If the gin context contains a pending_clients_count value (set by InjectPendingCount
// middleware), it is included in the navbar badge for admin users.
func buildNavbarProps(c *gin.Context, user *models.User, activeLink string) templates.NavbarProps {
	pendingCount := 0
	if v, exists := c.Get(ctxKeyPendingClientsCount); exists {
		if count, ok := v.(int); ok {
			pendingCount = count
		}
	}
	return templates.NavbarProps{
		Username:            user.Username,
		FullName:            user.FullName,
		IsAdmin:             user.IsAdmin(),
		ActiveLink:          activeLink,
		PendingClientsCount: pendingCount,
	}
}

// renderErrorPage renders the error page template with the given status code and message.
func renderErrorPage(c *gin.Context, statusCode int, message string) {
	templates.RenderTempl(c, statusCode, templates.ErrorPage(
		templates.ErrorPageProps{Error: message},
	))
}

// toPointerSlice converts a slice of values to a slice of pointers to those values.
func toPointerSlice[T any](s []T) []*T {
	ptrs := make([]*T, len(s))
	for i := range s {
		ptrs[i] = &s[i]
	}
	return ptrs
}
