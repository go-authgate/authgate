package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/templates"
)

// UserAdminHandler handles admin user management routes.
type UserAdminHandler struct {
	userService          *services.UserService
	tokenService         *services.TokenService
	authorizationService *services.AuthorizationService
}

// NewUserAdminHandler creates a new UserAdminHandler.
func NewUserAdminHandler(
	us *services.UserService,
	ts *services.TokenService,
	as *services.AuthorizationService,
) *UserAdminHandler {
	return &UserAdminHandler{
		userService:          us,
		tokenService:         ts,
		authorizationService: as,
	}
}

// adminGetUser fetches a user by ID and renders the appropriate error page on failure.
// Returns the user and true on success, or nil and false after rendering an error.
func (h *UserAdminHandler) adminGetUser(c *gin.Context) (*models.User, bool) {
	user, err := h.userService.AdminGetUserByID(c.Param("id"))
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			renderErrorPage(c, http.StatusNotFound, "User not found")
		} else {
			renderErrorPage(c, http.StatusInternalServerError, "Failed to load user")
		}
		return nil, false
	}
	user.PasswordHash = ""
	return user, true
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

	templates.RenderTempl(c, http.StatusOK, templates.AdminUsers(templates.UsersPageProps{
		BaseProps:        templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps:      buildNavbarProps(c, user, "users"),
		User:             user,
		Users:            users,
		Pagination:       pagination,
		Search:           params.Search,
		PageSize:         params.PageSize,
		Success:          getFlashMessage(c),
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

	targetUser, ok := h.adminGetUser(c)
	if !ok {
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

	templates.RenderTempl(c, http.StatusOK, templates.AdminUserDetail(templates.UserDetailPageProps{
		BaseProps:            templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps:          buildNavbarProps(c, currentUser, "users"),
		TargetUser:           targetUser,
		ActiveTokenCount:     stats.ActiveTokenCount,
		OAuthConnectionCount: stats.OAuthConnectionCount,
		AuthorizationCount:   stats.AuthorizationCount,
		Success:              getFlashMessage(c),
	}))
}

// ShowEditUserPage renders the user edit form.
func (h *UserAdminHandler) ShowEditUserPage(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, ok := h.adminGetUser(c)
	if !ok {
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

	targetUser, ok := h.adminGetUser(c)
	if !ok {
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

	flashAndRedirect(c, "User updated successfully.", "/admin/users/"+targetUser.ID)
}

// ResetPassword generates a new random password and displays it once.
func (h *UserAdminHandler) ResetPassword(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, ok := h.adminGetUser(c)
	if !ok {
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

	// Revoke all tokens so the user must re-authenticate with the new password.
	// If revocation fails, still show the password — the admin needs it to
	// communicate the new credential. A warning is displayed instead.
	var revokeWarning string
	if err := h.tokenService.RevokeAllUserTokens(targetUser.ID); err != nil {
		revokeWarning = "Warning: existing tokens could not be revoked. " +
			"The user may still have active sessions with the old password."
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
			Warning:     revokeWarning,
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

	// Validate before any side effects so guards (self-delete, last-admin)
	// reject the request without touching tokens.
	if err := h.userService.ValidateDeleteUser(userID, currentUser.ID); err != nil {
		switch {
		case errors.Is(err, services.ErrUserNotFound):
			renderErrorPage(c, http.StatusNotFound, err.Error())
		case errors.Is(err, services.ErrCannotDeleteSelf),
			errors.Is(err, services.ErrCannotRemoveLastAdmin):
			renderErrorPage(c, http.StatusBadRequest, err.Error())
		default:
			renderErrorPage(c, http.StatusInternalServerError, "Failed to delete user")
		}
		return
	}

	// Revoke tokens before deletion so no active tokens survive the user
	// being removed (ValidateToken does not check user existence).
	if err := h.tokenService.RevokeAllUserTokens(userID); err != nil {
		renderErrorPage(
			c,
			http.StatusInternalServerError,
			"Failed to revoke user tokens",
		)
		return
	}

	if err := h.userService.DeleteUserAdmin(
		c.Request.Context(),
		userID,
		currentUser.ID,
	); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	flashAndRedirect(c, "User deleted successfully.", "/admin/users")
}

// ── Create User ───────────────────────────────────────────────────────

// ShowCreateUserPage renders the user creation form.
func (h *UserAdminHandler) ShowCreateUserPage(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	templates.RenderTempl(c, http.StatusOK, templates.AdminUserCreate(templates.UserCreatePageProps{
		BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
		NavbarProps: buildNavbarProps(c, currentUser, "users"),
		Role:        models.UserRoleUser,
	}))
}

// CreateUser handles the user creation form submission.
func (h *UserAdminHandler) CreateUser(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	req := services.CreateUserRequest{
		Username: c.PostForm("username"),
		Email:    c.PostForm("email"),
		FullName: c.PostForm("full_name"),
		Role:     c.PostForm("role"),
		Password: c.PostForm("password"),
	}

	user, password, err := h.userService.CreateUserAdmin(
		c.Request.Context(),
		req,
		currentUser.ID,
	)
	if err != nil {
		// Distinguish user-facing validation errors from internal failures
		status := http.StatusBadRequest
		errMsg := err.Error()
		if !errors.Is(err, services.ErrUsernameRequired) &&
			!errors.Is(err, services.ErrEmailRequired) &&
			!errors.Is(err, services.ErrInvalidRole) &&
			!errors.Is(err, services.ErrUsernameConflict) &&
			!errors.Is(err, services.ErrEmailConflict) {
			status = http.StatusInternalServerError
			errMsg = "An internal error occurred. Please try again."
		}
		templates.RenderTempl(
			c,
			status,
			templates.AdminUserCreate(templates.UserCreatePageProps{
				BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
				NavbarProps: buildNavbarProps(c, currentUser, "users"),
				Error:       errMsg,
				Username:    req.Username,
				Email:       req.Email,
				FullName:    req.FullName,
				Role:        req.Role,
			}),
		)
		return
	}

	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	c.Header("Pragma", "no-cache")

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminUserCreated(templates.UserCreatedPageProps{
			BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: buildNavbarProps(c, currentUser, "users"),
			TargetUser:  user,
			NewPassword: password,
		}),
	)
}

// ── OAuth Connections ─────────────────────────────────────────────────

// ShowUserConnections renders the user's OAuth connections page.
func (h *UserAdminHandler) ShowUserConnections(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, ok := h.adminGetUser(c)
	if !ok {
		return
	}

	conns, err := h.userService.GetUserOAuthConnections(targetUser.ID)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to load OAuth connections")
		return
	}

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminUserConnections(templates.UserOAuthConnectionsPageProps{
			BaseProps:   templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps: buildNavbarProps(c, currentUser, "users"),
			TargetUser:  targetUser,
			Connections: conns,
			Success:     getFlashMessage(c),
		}),
	)
}

// DeleteUserConnection handles unlinking an OAuth connection.
func (h *UserAdminHandler) DeleteUserConnection(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userID := c.Param("id")
	connID := c.Param("conn_id")

	if err := h.userService.DeleteUserOAuthConnection(
		c.Request.Context(),
		userID,
		connID,
		currentUser.ID,
	); err != nil {
		if errors.Is(err, services.ErrOAuthConnectionNotFound) {
			renderErrorPage(c, http.StatusNotFound, err.Error())
		} else {
			renderErrorPage(c, http.StatusInternalServerError, "Failed to remove OAuth connection")
		}
		return
	}

	flashAndRedirect(
		c,
		"OAuth connection removed successfully.",
		"/admin/users/"+userID+"/connections",
	)
}

// ── User Authorizations ───────────────────────────────────────────────

// ShowUserAuthorizations renders the user's authorized apps page.
func (h *UserAdminHandler) ShowUserAuthorizations(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	targetUser, ok := h.adminGetUser(c)
	if !ok {
		return
	}

	auths, err := h.authorizationService.ListUserAuthorizations(
		c.Request.Context(),
		targetUser.ID,
	)
	if err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to load authorizations")
		return
	}

	// Convert to display models
	displayAuths := make([]templates.AuthorizationDisplay, 0, len(auths))
	for _, a := range auths {
		displayAuths = append(displayAuths, templates.AuthorizationDisplay{
			UUID:       a.UUID,
			ClientID:   a.ClientID,
			ClientName: a.ClientName,
			Scopes:     a.Scopes,
			GrantedAt:  a.GrantedAt,
			IsActive:   a.IsActive,
		})
	}

	templates.RenderTempl(
		c,
		http.StatusOK,
		templates.AdminUserAuthorizations(templates.UserAuthorizationsPageProps{
			BaseProps:      templates.BaseProps{CSRFToken: middleware.GetCSRFToken(c)},
			NavbarProps:    buildNavbarProps(c, currentUser, "users"),
			TargetUser:     targetUser,
			Authorizations: displayAuths,
			Success:        getFlashMessage(c),
		}),
	)
}

// RevokeUserAuthorization handles revoking a user's app authorization.
func (h *UserAdminHandler) RevokeUserAuthorization(c *gin.Context) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userID := c.Param("id")
	authUUID := c.Param("uuid")

	if err := h.authorizationService.RevokeUserAuthorization(
		c.Request.Context(),
		authUUID,
		userID,
	); err != nil {
		if errors.Is(err, services.ErrAuthorizationNotFound) {
			renderErrorPage(c, http.StatusNotFound, err.Error())
		} else {
			renderErrorPage(c, http.StatusInternalServerError, "Failed to revoke authorization")
		}
		return
	}

	flashAndRedirect(
		c,
		"Authorization revoked successfully.",
		"/admin/users/"+userID+"/authorizations",
	)
}

// ── Disable/Enable User ───────────────────────────────────────────────

// DisableUser handles disabling a user account.
func (h *UserAdminHandler) DisableUser(c *gin.Context) {
	h.toggleUserActive(c, false)
}

// EnableUser handles enabling a user account.
func (h *UserAdminHandler) EnableUser(c *gin.Context) {
	h.toggleUserActive(c, true)
}

// toggleUserActive is the shared implementation for DisableUser and EnableUser.
func (h *UserAdminHandler) toggleUserActive(c *gin.Context, active bool) {
	currentUser := getUserFromContext(c)
	if currentUser == nil {
		renderErrorPage(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userID := c.Param("id")

	// Validate first so we don't revoke tokens if the operation will be rejected.
	if err := h.userService.ValidateSetUserActiveStatus(
		userID,
		currentUser.ID,
		active,
	); err != nil {
		switch {
		case errors.Is(err, services.ErrCannotDisableSelf),
			errors.Is(err, services.ErrUserAlreadyActive),
			errors.Is(err, services.ErrUserAlreadyDisabled),
			errors.Is(err, services.ErrCannotRemoveLastAdmin):
			renderErrorPage(c, http.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrUserNotFound):
			renderErrorPage(c, http.StatusNotFound, "User not found")
		default:
			renderErrorPage(
				c,
				http.StatusInternalServerError,
				"Failed to validate user status change",
			)
		}
		return
	}

	// When disabling, revoke all tokens BEFORE changing status to close the
	// window where a disabled user's tokens could still be valid.
	if !active {
		if err := h.tokenService.RevokeAllUserTokens(userID); err != nil {
			renderErrorPage(
				c,
				http.StatusInternalServerError,
				"Failed to revoke user tokens",
			)
			return
		}
	}

	if err := h.userService.SetUserActiveStatus(
		c.Request.Context(),
		userID,
		currentUser.ID,
		active,
	); err != nil {
		renderErrorPage(c, http.StatusInternalServerError, "Failed to update user status")
		return
	}

	msg := "User account has been enabled."
	if !active {
		msg = "User account has been disabled."
	}
	flashAndRedirect(c, msg, "/admin/users/"+userID)
}
