package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSessionServices creates the store and services needed for session tests
// without building a Gin router (each test wires its own routes with appropriate middleware).
func setupSessionServices(t *testing.T) (*store.Store, *services.TokenService) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		JWTExpiration: 1 * time.Hour,
		JWTSecret:     "test-secret-32-chars-long!!!!!!!",
		BaseURL:       "http://localhost:8080",
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	localProvider := token.NewLocalTokenProvider(cfg)
	auditSvc := services.NewAuditService(s, false, 0)
	deviceSvc := services.NewDeviceService(s, cfg, auditSvc, metrics.NewNoopMetrics())
	tokenSvc := services.NewTokenService(
		s, cfg, deviceSvc, localProvider, auditSvc, metrics.NewNoopMetrics(),
	)

	return s, tokenSvc
}

func createTestToken(t *testing.T, s *store.Store, userID, clientID string) *models.AccessToken {
	t.Helper()
	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(uuid.New().String()),
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        userID,
		ClientID:      clientID,
		Scopes:        "email profile",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, s.CreateAccessToken(tok))
	return tok
}

// newSessionRouter creates a Gin router with the session handler and optional user_id injection.
func newSessionRouter(handler *SessionHandler, userID string) *gin.Engine {
	r := gin.New()
	if userID != "" {
		r.Use(func(c *gin.Context) {
			c.Set("user_id", userID)
			c.Next()
		})
	}
	r.POST("/account/sessions/:id/revoke", handler.RevokeSession)
	r.POST("/account/sessions/:id/disable", handler.DisableSession)
	r.POST("/account/sessions/:id/enable", handler.EnableSession)
	r.POST("/account/sessions/revoke-all", handler.RevokeAllSessions)
	return r
}

func TestRevokeSession_Success(t *testing.T) {
	s, tokenSvc := setupSessionServices(t)
	userID := uuid.New().String()
	tok := createTestToken(t, s, userID, uuid.New().String())

	handler := NewSessionHandler(tokenSvc, nil)
	r := newSessionRouter(handler, userID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/sessions/"+tok.ID+"/revoke", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)

	// Verify token was revoked
	_, err := s.GetAccessTokenByID(tok.ID)
	assert.Error(t, err) // deleted
}

func TestRevokeSession_NotOwned(t *testing.T) {
	s, tokenSvc := setupSessionServices(t)
	ownerID := uuid.New().String()
	attackerID := uuid.New().String()
	tok := createTestToken(t, s, ownerID, uuid.New().String())

	handler := NewSessionHandler(tokenSvc, nil)
	r := newSessionRouter(handler, attackerID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/sessions/"+tok.ID+"/revoke", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRevokeSession_Unauthenticated(t *testing.T) {
	_, tokenSvc := setupSessionServices(t)
	handler := NewSessionHandler(tokenSvc, nil)
	r := newSessionRouter(handler, "") // no user_id

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/sessions/some-id/revoke", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDisableAndEnableSession(t *testing.T) {
	s, tokenSvc := setupSessionServices(t)
	userID := uuid.New().String()
	tok := createTestToken(t, s, userID, uuid.New().String())

	handler := NewSessionHandler(tokenSvc, nil)
	r := newSessionRouter(handler, userID)

	// Disable
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/sessions/"+tok.ID+"/disable", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)

	disabled, err := s.GetAccessTokenByID(tok.ID)
	require.NoError(t, err)
	assert.Equal(t, models.TokenStatusDisabled, disabled.Status)

	// Enable
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/account/sessions/"+tok.ID+"/enable", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)

	enabled, err := s.GetAccessTokenByID(tok.ID)
	require.NoError(t, err)
	assert.Equal(t, models.TokenStatusActive, enabled.Status)
}

func TestRevokeAllSessions(t *testing.T) {
	s, tokenSvc := setupSessionServices(t)
	userID := uuid.New().String()
	clientID := uuid.New().String()
	createTestToken(t, s, userID, clientID)
	createTestToken(t, s, userID, clientID)

	handler := NewSessionHandler(tokenSvc, nil)
	r := newSessionRouter(handler, userID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/account/sessions/revoke-all", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)

	tokens, err := s.GetTokensByUserID(userID)
	require.NoError(t, err)
	assert.Empty(t, tokens)
}
