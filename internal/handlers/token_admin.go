package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

const adminTokensPath = "/admin/tokens"

var (
	validTokenStatuses = map[string]bool{
		models.TokenStatusActive:   true,
		models.TokenStatusDisabled: true,
		models.TokenStatusRevoked:  true,
	}
	validTokenCategories = map[string]bool{
		models.TokenCategoryAccess:  true,
		models.TokenCategoryRefresh: true,
	}
)

// tokenSuccessMessages maps success codes to human-readable messages.
var tokenSuccessMessages = map[string]string{
	"revoked":  "Token has been permanently revoked.",
	"disabled": "Token has been disabled. It can be re-enabled later.",
	"enabled":  "Token has been re-enabled.",
}

// tokenWarningMessages maps warning codes to human-readable messages.
var tokenWarningMessages = map[string]string{
	"cannot_disable": "Token cannot be disabled (only active tokens can be disabled).",
	"cannot_enable":  "Token cannot be enabled (only disabled tokens can be re-enabled).",
}

type TokenAdminHandler struct {
	tokenService *services.TokenService
}

func NewTokenAdminHandler(ts *services.TokenService) *TokenAdminHandler {
	return &TokenAdminHandler{tokenService: ts}
}

func (h *TokenAdminHandler) ShowTokensPage(c *gin.Context) {
	user := getUserFromContext(c)
	if user == nil {
		renderErrorPage(c, http.StatusUnauthorized, "User not authenticated")
		return
	}

	params := parseTokenPaginationParams(c)

	tokens, pagination, err := h.tokenService.ListAllTokensPaginated(params)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to retrieve tokens")
		return
	}

	templates.RenderTempl(c, http.StatusOK, templates.AdminTokens(templates.TokensPageProps{
		BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps:    buildNavbarProps(c, user, "tokens"),
		Tokens:         tokens,
		Pagination:     pagination,
		Search:         params.Search,
		PageSize:       params.PageSize,
		StatusFilter:   params.StatusFilter,
		CategoryFilter: params.CategoryFilter,
		Success:        tokenSuccessMessages[c.Query("success")],
		Warning:        tokenWarningMessages[c.Query("warning")],
		Now:            time.Now(),
	}))
}

// tokenAction extracts tokenID + userID, calls the service method, and
// redirects back to the token list with a success or warning code.
func (h *TokenAdminHandler) tokenAction(
	c *gin.Context,
	action func(ctx context.Context, tokenID, userID string) error,
	businessErr error,
	warningCode, successCode string,
) {
	tokenID := c.Param("id")
	if tokenID == "" {
		renderErrorPage(c, http.StatusBadRequest, "Token ID is required")
		return
	}

	userID := getUserIDFromContext(c)

	if err := action(c.Request.Context(), tokenID, userID); err != nil {
		if businessErr != nil && errors.Is(err, businessErr) {
			q := c.Request.URL.Query()
			q.Set("warning", warningCode)
			c.Redirect(http.StatusFound, adminTokensPath+"?"+q.Encode())
			return
		}
		renderErrorPage(c, http.StatusInternalServerError, "Failed to update token")
		return
	}

	q := c.Request.URL.Query()
	q.Set("success", successCode)
	c.Redirect(http.StatusFound, adminTokensPath+"?"+q.Encode())
}

func (h *TokenAdminHandler) RevokeToken(c *gin.Context) {
	h.tokenAction(c,
		h.tokenService.RevokeTokenByID, nil, "",
		"revoked")
}

func (h *TokenAdminHandler) DisableToken(c *gin.Context) {
	h.tokenAction(c,
		h.tokenService.DisableToken,
		services.ErrTokenCannotDisable,
		"cannot_disable",
		"disabled")
}

func (h *TokenAdminHandler) EnableToken(c *gin.Context) {
	h.tokenAction(c,
		h.tokenService.EnableToken,
		services.ErrTokenCannotEnable,
		"cannot_enable",
		"enabled")
}
