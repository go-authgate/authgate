package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"
)

// UserAdminHandler handles admin user management routes.
type UserAdminHandler struct {
	userService  *services.UserService
	tokenService *services.TokenService
}

// NewUserAdminHandler creates a new UserAdminHandler.
func NewUserAdminHandler(us *services.UserService, ts *services.TokenService) *UserAdminHandler {
	return &UserAdminHandler{userService: us, tokenService: ts}
}

// ShowUsersPage renders the paginated user list.
func (h *UserAdminHandler) ShowUsersPage(c *gin.Context) {
	user := getUserFromContext(c)
	if user == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	params := parsePaginationParams(c)
	params.StatusFilter = c.Query("role")          // reuse as role filter
	params.CategoryFilter = c.Query("auth_source") // reuse as auth_source filter

	users, pagination, err := h.userService.ListUsersPaginated(params)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to load users")
		return
	}

	// Retrieve flash messages
	session := sessions.Default(c)
	flashes := session.Flashes()
	if err := session.Save(); err != nil {
		c.Set("session_save_error", err)
	}

	var successMsg string
	if len(flashes) > 0 {
		if msg, ok := flashes[0].(string); ok {
			successMsg = msg
		}
	}

	templates.RenderTempl(c, http.StatusOK, templates.AdminUsers(templates.UsersPageProps{
		BaseProps:        templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps:      buildNavbarProps(c, user, "users"),
		User:             user,
		Users:            users,
		Pagination:       pagination,
		Search:           params.Search,
		PageSize:         params.PageSize,
		Success:          successMsg,
		RoleFilter:       params.StatusFilter,
		AuthSourceFilter: params.CategoryFilter,
	}))
}

// ViewUser renders the user detail page.
func (h *UserAdminHandler) ViewUser(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, err := h.userService.AdminGetUserByID(c.Param("id"))
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "User not found")
		return
	}

	stats, err := h.userService.GetUserStats(targetUser.ID)
	if err != nil {
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Failed to load user stats",
		)
		return
	}

	// Retrieve flash messages
	session := sessions.Default(c)
	flashes := session.Flashes()
	if err := session.Save(); err != nil {
		c.Set("session_save_error", err)
	}

	var successMsg string
	if len(flashes) > 0 {
		if msg, ok := flashes[0].(string); ok {
			successMsg = msg
		}
	}

	templates.RenderTempl(c, http.StatusOK, templates.AdminUserDetail(templates.UserDetailPageProps{
		BaseProps:            templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps:          buildNavbarProps(c, currentUser, "users"),
		TargetUser:           targetUser,
		ActiveTokenCount:     stats.ActiveTokenCount,
		OAuthConnectionCount: stats.OAuthConnectionCount,
		AuthorizationCount:   stats.AuthorizationCount,
		Success:              successMsg,
	}))
}

// ShowEditUserPage renders the user edit form.
func (h *UserAdminHandler) ShowEditUserPage(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, err := h.userService.AdminGetUserByID(c.Param("id"))
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "User not found")
		return
	}

	templates.RenderTempl(c, http.StatusOK, templates.AdminUserForm(templates.UserFormPageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, currentUser, "users"),
		TargetUser:  targetUser,
		IsSelf:      currentUser.ID == targetUser.ID,
	}))
}

// UpdateUser handles the user update form submission.
func (h *UserAdminHandler) UpdateUser(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, err := h.userService.AdminGetUserByID(c.Param("id"))
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "User not found")
		return
	}

	req := services.UpdateUserProfileRequest{
		FullName: c.PostForm("full_name"),
		Email:    c.PostForm("email"),
		Role:     c.PostForm("role"),
	}

	if err := h.userService.UpdateUserProfile(
		c.Request.Context(),
		targetUser.ID,
		currentUser.ID,
		req,
	); err != nil {
		// Re-render form with error
		targetUser.FullName = req.FullName
		targetUser.Email = req.Email
		if req.Role != "" {
			targetUser.Role = req.Role
		}
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.AdminUserForm(templates.UserFormPageProps{
				BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: buildNavbarProps(c, currentUser, "users"),
				TargetUser:  targetUser,
				Error:       err.Error(),
				IsSelf:      currentUser.ID == targetUser.ID,
			}),
		)
		return
	}

	session := sessions.Default(c)
	session.AddFlash("User updated successfully.")
	if err := session.Save(); err != nil {
		c.Set("session_save_error", err)
	}

	c.Redirect(http.StatusFound, "/admin/users/"+targetUser.ID)
}

// ResetPassword generates a new random password and displays it once.
func (h *UserAdminHandler) ResetPassword(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, err := h.userService.AdminGetUserByID(c.Param("id"))
	if err != nil {
		renderErrorPage(c, http.StatusNotFound, "User not found")
		return
	}

	newPassword, err := h.userService.ResetUserPassword(
		c.Request.Context(),
		targetUser.ID,
		currentUser.ID,
	)
	if err != nil {
		templates.RenderTempl(
			c,
			http.StatusBadRequest,
			templates.AdminUserDetail(templates.UserDetailPageProps{
				BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: buildNavbarProps(c, currentUser, "users"),
				TargetUser:  targetUser,
				Error:       err.Error(),
			}),
		)
		return
	}

	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	c.Header("Pragma", "no-cache")

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminUserPasswordReset(templates.UserPasswordResetPageProps{
			BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: buildNavbarProps(c, currentUser, "users"),
			TargetUser:  targetUser,
			NewPassword: newPassword,
		}),
	)
}

// DeleteUser handles user deletion.
func (h *UserAdminHandler) DeleteUser(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userID := c.Param("id")

	if err := h.userService.DeleteUserAdmin(
		c.Request.Context(),
		userID,
		currentUser.ID,
	); err != nil {
		msg := "Failed to delete user"
		if errors.Is(err, services.ErrCannotDeleteSelf) ||
			errors.Is(err, services.ErrCannotRemoveLastAdmin) ||
			errors.Is(err, services.ErrUserNotFound) {
			msg = err.Error()
		}
		renderErrorPage(c, http.StatusBadRequest, msg)
		return
	}

	// Revoke tokens after successful deletion (invalidates token cache).
	// Orphaned tokens are harmless — validation will fail since the user no longer exists.
	if err := h.tokenService.RevokeAllUserTokens(userID); err != nil {
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"User deleted but failed to revoke tokens",
		)
		return
	}

	session := sessions.Default(c)
	session.AddFlash("User deleted successfully")
	if err := session.Save(); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to save session")
		return
	}

	c.Redirect(http.StatusFound, "/admin/users")
}
