package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/templates"

	"github.com/gin-gonic/gin"
)

type SessionHandler struct {
	tokenService *services.TokenService
	userService  *services.UserService
}

func NewSessionHandler(ts *services.TokenService, us *services.UserService) *SessionHandler {
	return &SessionHandler{
		tokenService: ts,
		userService:  us,
	}
}

// ListSessions shows all active sessions (tokens) for the current user
func (h *SessionHandler) ListSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		renderErrorPage(c, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	search := c.Query("search")

	// Create pagination params
	params := store.NewPaginationParams(page, pageSize, search)

	// Get paginated tokens
	tokens, pagination, err := h.tokenService.GetUserTokensWithClientPaginated(
		userID.(string),
		params,
	)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to retrieve sessions")
		return
	}

	// Get user info for navbar
	user, err := h.userService.GetUserByID(userID.(string))
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to retrieve user information")
		return
	}

	templates.RenderTempl(c, http.StatusOK, templates.AccountSessions(templates.SessionsPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(user, "sessions"),
		Sessions:    tokens,
		Pagination:  pagination,
		Search:      search,
		PageSize:    pageSize,
	}))
}

// validateTokenOwnership checks if the current user owns the specified token.
// Returns the tokenID if valid, otherwise renders error and returns empty string.
func (h *SessionHandler) validateTokenOwnership(
	c *gin.Context,
	actionName string,
) (tokenID string, valid bool) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		renderErrorPage(c, http.StatusUnauthorized, "User not authenticated")
		return "", false
	}

	tokenID = c.Param("id")
	if tokenID == "" {
		renderErrorPage(c, http.StatusBadRequest, "Token ID is required")
		return "", false
	}

	userID := userIDVal.(string)

	owned, err := h.tokenService.IsTokenOwnedByUser(tokenID, userID)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to retrieve sessions")
		return "", false
	}

	if !owned {
		renderErrorPage(
			c,
			http.StatusForbidden,
			"You don't have permission to "+actionName+" this token",
		)
		return "", false
	}

	return tokenID, true
}

// RevokeSession revokes a specific session by token ID
func (h *SessionHandler) RevokeSession(c *gin.Context) {
	tokenID, valid := h.validateTokenOwnership(c, "revoke")
	if !valid {
		return
	}

	userID, _ := c.Get("user_id")

	// Revoke the token
	if err := h.tokenService.RevokeTokenByID(
		c.Request.Context(),
		tokenID,
		userID.(string),
	); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to revoke session")
		return
	}

	c.Redirect(http.StatusFound, "/account/sessions")
}

// RevokeAllSessions revokes all sessions for the current user
func (h *SessionHandler) RevokeAllSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		renderErrorPage(c, http.StatusUnauthorized, "User not authenticated")
		return
	}

	if err := h.tokenService.RevokeAllUserTokens(userID.(string)); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to revoke all sessions")
		return
	}

	c.Redirect(http.StatusFound, "/account/sessions")
}

// DisableSession temporarily disables a specific session by token ID
func (h *SessionHandler) DisableSession(c *gin.Context) {
	tokenID, valid := h.validateTokenOwnership(c, "disable")
	if !valid {
		return
	}

	userID, _ := c.Get("user_id")

	// Disable the token
	if err := h.tokenService.DisableToken(
		c.Request.Context(),
		tokenID,
		userID.(string),
	); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to disable session")
		return
	}

	c.Redirect(http.StatusFound, "/account/sessions")
}

// EnableSession re-enables a previously disabled session by token ID
func (h *SessionHandler) EnableSession(c *gin.Context) {
	tokenID, valid := h.validateTokenOwnership(c, "enable")
	if !valid {
		return
	}

	userID, _ := c.Get("user_id")

	// Enable the token
	if err := h.tokenService.EnableToken(
		c.Request.Context(),
		tokenID,
		userID.(string),
	); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to enable session")
		return
	}

	c.Redirect(http.StatusFound, "/account/sessions")
}
