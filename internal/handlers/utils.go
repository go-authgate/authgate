package handlers

import (
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

const ctxKeyPendingClientsCount = "pending_clients_count"

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
