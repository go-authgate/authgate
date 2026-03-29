package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDeviceTestEnv(t *testing.T) (*gin.Engine, *store.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		BaseURL:              "http://localhost:8080",
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	auditSvc := services.NewNoopAuditService()
	deviceSvc := services.NewDeviceService(s, cfg, auditSvc, metrics.NewNoopMetrics())
	userSvc := services.NewUserService(s, nil, nil, "local", false, auditSvc, nil, 0)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, nil)
	handler := NewDeviceHandler(deviceSvc, userSvc, authzSvc, cfg)

	r := gin.New()
	r.POST("/oauth/device/code", handler.DeviceCodeRequest)

	return r, s
}

func createDeviceFlowClient(
	t *testing.T,
	s *store.Store,
	active bool,
	deviceFlowEnabled bool,
) *models.OAuthApplication {
	t.Helper()
	status := models.ClientStatusActive
	if !active {
		status = models.ClientStatusInactive
	}
	client := &models.OAuthApplication{
		ClientID:         uuid.New().String(),
		ClientName:       "Device Test Client",
		UserID:           uuid.New().String(),
		Scopes:           "email profile",
		GrantTypes:       "device_code",
		EnableDeviceFlow: deviceFlowEnabled,
		Status:           status,
	}
	require.NoError(t, s.CreateClient(client))
	return client
}

func TestDeviceCodeRequest_Success(t *testing.T) {
	r, s := setupDeviceTestEnv(t)
	client := createDeviceFlowClient(t, s, true, true)

	w := httptest.NewRecorder()
	form := url.Values{"client_id": {client.ClientID}, "scope": {"email"}}
	req, _ := http.NewRequest(
		http.MethodPost,
		"/oauth/device/code",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["device_code"])
	assert.NotEmpty(t, resp["user_code"])
	assert.Contains(t, resp["verification_uri"], "/device")
	assert.NotZero(t, resp["expires_in"])
	assert.NotZero(t, resp["interval"])
}

func TestDeviceCodeRequest_MissingClientID(t *testing.T) {
	r, _ := setupDeviceTestEnv(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oauth/device/code", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_request", resp["error"])
}

func TestDeviceCodeRequest_UnknownClient(t *testing.T) {
	r, _ := setupDeviceTestEnv(t)

	w := httptest.NewRecorder()
	form := url.Values{"client_id": {"nonexistent-client"}}
	req, _ := http.NewRequest(
		http.MethodPost,
		"/oauth/device/code",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestDeviceCodeRequest_InactiveClient(t *testing.T) {
	r, s := setupDeviceTestEnv(t)
	client := createDeviceFlowClient(t, s, false, true)

	w := httptest.NewRecorder()
	form := url.Values{"client_id": {client.ClientID}}
	req, _ := http.NewRequest(
		http.MethodPost,
		"/oauth/device/code",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestDeviceCodeRequest_DeviceFlowNotEnabled(t *testing.T) {
	r, s := setupDeviceTestEnv(t)
	// Create client with device flow enabled first, then disable it
	// (GORM default:true skips zero-value false on insert)
	client := createDeviceFlowClient(t, s, true, true)
	client.EnableDeviceFlow = false
	require.NoError(t, s.UpdateClient(client))

	w := httptest.NewRecorder()
	form := url.Values{"client_id": {client.ClientID}}
	req, _ := http.NewRequest(
		http.MethodPost,
		"/oauth/device/code",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "unauthorized_client", resp["error"])
}

func TestDeviceCodeRequest_JSONBody(t *testing.T) {
	r, s := setupDeviceTestEnv(t)
	client := createDeviceFlowClient(t, s, true, true)

	w := httptest.NewRecorder()
	body := `{"client_id":"` + client.ClientID + `","scope":"profile"}`
	req, _ := http.NewRequest(http.MethodPost, "/oauth/device/code", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["device_code"])
}

func TestDeviceCodeRequest_DefaultScope(t *testing.T) {
	r, s := setupDeviceTestEnv(t)
	client := createDeviceFlowClient(t, s, true, true)

	w := httptest.NewRecorder()
	form := url.Values{"client_id": {client.ClientID}}
	req, _ := http.NewRequest(
		http.MethodPost,
		"/oauth/device/code",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["device_code"])
	assert.NotEmpty(t, resp["user_code"])
}

func TestDeviceCodeErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"not found", services.ErrUserCodeNotFound, "User code not found"},
		{"expired", services.ErrDeviceCodeExpired, "Code has expired, please request a new one"},
		{
			"already authorized",
			services.ErrDeviceCodeAlreadyAuthorized,
			"This code has already been authorized",
		},
		{"unknown error", errors.New("unexpected failure"), "Invalid or expired code"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, deviceCodeErrorMessage(tc.err))
		})
	}
}
