package handlers

import (
	"net/http"

	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

// DashboardHandler serves the admin dashboard page.
type DashboardHandler struct {
	dashboardService *services.DashboardService
}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler(ds *services.DashboardService) *DashboardHandler {
	return &DashboardHandler{dashboardService: ds}
}

// ShowDashboard renders the admin dashboard with system metrics and recent activity.
func (h *DashboardHandler) ShowDashboard(c *gin.Context) {
	user := getUserFromContext(c)
	if user == nil {
		renderErrorPage(c, http.StatusUnauthorized, "User not authenticated")
		return
	}

	stats := h.dashboardService.GetDashboardStats(c.Request.Context())

	templates.RenderTempl(c, http.StatusOK, templates.AdminDashboard(templates.DashboardPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, user, "dashboard"),
		Stats:       *stats,
	}))
}
