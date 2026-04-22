package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// parsePaginationParams extracts page, page_size, and search query params.
func parsePaginationParams(c *gin.Context) store.PaginationParams {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	search := c.Query("search")
	return store.NewPaginationParams(page, pageSize, search)
}

// parseClientCredentials extracts client_id and client_secret from the request
// using HTTP Basic Auth (preferred per RFC 6749 §2.3.1) or form-body parameters.
func parseClientCredentials(c *gin.Context) (clientID, clientSecret string) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	return clientID, clientSecret
}

// respondOAuthError writes an RFC-compliant OAuth error JSON response.
func respondOAuthError(c *gin.Context, status int, errorCode, description string) {
	resp := gin.H{"error": errorCode}
	if description != "" {
		resp["error_description"] = description
	}
	c.JSON(status, resp)
}

// getUserIDFromContext returns the user ID string stored by RequireAuth middleware,
// or an empty string if no user ID is present.
func getUserIDFromContext(c *gin.Context) string {
	if id, exists := c.Get("user_id"); exists {
		if userID, ok := id.(string); ok {
			return userID
		}
	}
	return ""
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
		TokenProfile:                app.TokenProfile,
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
		DocsNavEntries:      NavbarDocsEntriesFor(resolveLocale(c)),
	}
}

// parseTokenPaginationParams extends parsePaginationParams with token-specific
// status and category filters from query params.
func parseTokenPaginationParams(c *gin.Context) store.PaginationParams {
	params := parsePaginationParams(c)
	if s := c.Query("status"); validTokenStatuses[s] {
		params.StatusFilter = s
	}
	if cat := c.Query("category"); validTokenCategories[cat] {
		params.CategoryFilter = cat
	}
	return params
}

// getFlashMessage retrieves and clears the first flash message from the session.
// A failed session.Save here only loses the just-cleared flash (a UX nicety),
// so we log and continue rather than fail the request.
func getFlashMessage(c *gin.Context) string {
	session := sessions.Default(c)
	flashes := session.Flashes()
	if err := session.Save(); err != nil {
		log.Printf("[Session] Failed to save session after reading flash: %v", err)
	}
	if len(flashes) > 0 {
		if msg, ok := flashes[0].(string); ok {
			return msg
		}
	}
	return ""
}

// flashAndRedirect sets a flash message and redirects to the given URL.
// A failed session.Save here only drops the flash message, so we log and
// continue with the redirect rather than fail the request.
func flashAndRedirect(c *gin.Context, msg, url string) {
	session := sessions.Default(c)
	session.AddFlash(msg)
	if err := session.Save(); err != nil {
		log.Printf("[Session] Failed to save flash message: %v", err)
	}
	c.Redirect(http.StatusFound, url)
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

// toAuthorizationDisplaySlice converts service-layer authorization details
// to template display models.
func toAuthorizationDisplaySlice(
	auths []services.UserAuthorizationWithClient,
) []templates.AuthorizationDisplay {
	display := make([]templates.AuthorizationDisplay, 0, len(auths))
	for _, a := range auths {
		display = append(display, templates.AuthorizationDisplay{
			UUID:       a.UUID,
			ClientID:   a.ClientID,
			ClientName: a.ClientName,
			Scopes:     a.Scopes,
			GrantedAt:  a.GrantedAt,
			IsActive:   a.IsActive,
		})
	}
	return display
}
