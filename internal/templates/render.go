package templates

import (
	"net/http"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"
)

// RenderTempl renders a templ component to a Gin context
func RenderTempl(c *gin.Context, status int, component templ.Component) {
	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")

	if err := component.Render(c.Request.Context(), c.Writer); err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
	}
}
