package handlers

import (
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

// buildNavbarProps creates NavbarProps from a user model and active link identifier.
func buildNavbarProps(user *models.User, activeLink string) templates.NavbarProps {
	return templates.NavbarProps{
		Username:   user.Username,
		FullName:   user.FullName,
		IsAdmin:    user.IsAdmin(),
		ActiveLink: activeLink,
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
