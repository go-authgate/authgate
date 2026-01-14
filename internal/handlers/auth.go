package handlers

import (
	"errors"
	"net/http"

	"github.com/appleboy/authgate/internal/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionUserID   = "user_id"
	SessionUsername = "username"
)

type AuthHandler struct {
	userService *services.UserService
}

func NewAuthHandler(us *services.UserService) *AuthHandler {
	return &AuthHandler{userService: us}
}

// LoginPage renders the login page
func (h *AuthHandler) LoginPage(c *gin.Context) {
	session := sessions.Default(c)
	if session.Get(SessionUserID) != nil {
		// Already logged in, redirect to device page
		c.Redirect(http.StatusFound, "/device")
		return
	}

	redirectTo := c.Query("redirect")
	c.HTML(http.StatusOK, "login.html", gin.H{
		"redirect": redirectTo,
		"error":    c.Query("error"),
	})
}

// Login handles the login form submission
func (h *AuthHandler) Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirectTo := c.PostForm("redirect")

	user, err := h.userService.Authenticate(c.Request.Context(), username, password)
	if err != nil {
		var errorMsg string

		// Check for specific error types
		if errors.Is(err, services.ErrUsernameConflict) {
			errorMsg = "Username conflict with existing user. Please contact administrator."
		} else {
			errorMsg = "Invalid username or password"
		}

		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error":    errorMsg,
			"redirect": redirectTo,
		})
		return
	}

	// Set session
	session := sessions.Default(c)
	session.Set(SessionUserID, user.ID)
	session.Set(SessionUsername, user.Username)
	if err := session.Save(); err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"error": "Failed to create session",
		})
		return
	}

	// Redirect
	if redirectTo != "" {
		c.Redirect(http.StatusFound, redirectTo)
	} else {
		c.Redirect(http.StatusFound, "/device")
	}
}

// Logout clears the session and redirects to login
func (h *AuthHandler) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save session",
		})
		return
	}
	c.Redirect(http.StatusFound, "/login")
}
