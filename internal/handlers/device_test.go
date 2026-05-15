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

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
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
	clientSvc := services.NewClientService(s, auditSvc, nil, 0, nil, 0)
	deviceSvc := services.NewDeviceService(s, cfg, auditSvc, metrics.NewNoopMetrics(), clientSvc)
	userSvc := services.NewUserService(s, nil, nil, "local", false, auditSvc, nil, 0)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, nil, clientSvc)
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

// TestDeviceCodeRequest_WithResource_PersistsOnDeviceCode confirms the new
// `resource` form parameter is parsed, validated, and stored on the device
// code so the polling /oauth/token grant can subset-check against it. Two
// repeated `resource` values exercise the multi-value path.
func TestDeviceCodeRequest_WithResource_PersistsOnDeviceCode(t *testing.T) {
	r, s := setupDeviceTestEnv(t)
	client := createDeviceFlowClient(t, s, true, true)

	w := httptest.NewRecorder()
	form := url.Values{
		"client_id": {client.ClientID},
		"scope":     {"email"},
		"resource":  {"https://mcp1.example.com", "https://mcp2.example.com"},
	}
	req, _ := http.NewRequest(
		http.MethodPost,
		"/oauth/device/code",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	deviceCode, ok := resp["device_code"].(string)
	require.True(t, ok)

	// Look up the persisted row by its ID suffix and verify Resource is set.
	candidates, err := s.GetDeviceCodesByID(deviceCode[len(deviceCode)-8:])
	require.NoError(t, err)
	require.NotEmpty(t, candidates)
	assert.Equal(
		t,
		models.StringArray{"https://mcp1.example.com", "https://mcp2.example.com"},
		candidates[0].Resource,
		"resource form param must be persisted on the device code row",
	)
}

// TestDeviceCodeRequest_InvalidResource_ReturnsInvalidTarget exercises the
// validation path: a malformed resource (here, one with a fragment, which
// RFC 8707 §2.1 forbids) must be rejected with the OAuth 2.0 invalid_target
// error code rather than persisted.
func TestDeviceCodeRequest_InvalidResource_ReturnsInvalidTarget(t *testing.T) {
	r, s := setupDeviceTestEnv(t)
	client := createDeviceFlowClient(t, s, true, true)

	w := httptest.NewRecorder()
	form := url.Values{
		"client_id": {client.ClientID},
		"resource":  {"https://mcp.example.com/api#frag"},
	}
	req, _ := http.NewRequest(
		http.MethodPost,
		"/oauth/device/code",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_target", resp["error"])
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

// ============================================================
// DeviceVerify — resource-bound confirm page
// ============================================================

// setupDeviceVerifyEnv wires up POST /device/verify against an in-memory
// store with sessions middleware that auto-populates the logged-in user.
// Returns the engine, the test store, and a seeded user/client/device-code
// triple. The device code is unauthorized; resource is set per the caller.
func setupDeviceVerifyEnv(
	t *testing.T,
	resource []string,
) (*gin.Engine, *store.Store, *models.OAuthApplication, *models.User, *models.DeviceCode) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		BaseURL:              "http://localhost:8080",
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	auditSvc := services.NewNoopAuditService()
	clientSvc := services.NewClientService(s, auditSvc, nil, 0, nil, 0)
	deviceSvc := services.NewDeviceService(
		s, cfg, auditSvc, metrics.NewNoopMetrics(), clientSvc,
	)
	userSvc := services.NewUserService(
		s, nil, nil, "local", false, auditSvc,
		cache.NewNoopCache[models.User](), 0,
	)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, nil, clientSvc)
	handler := NewDeviceHandler(deviceSvc, userSvc, authzSvc, cfg)

	client := &models.OAuthApplication{
		ClientID:         uuid.New().String(),
		ClientSecret:     "test-secret-hash",
		ClientName:       "Device Confirm Test Client",
		UserID:           uuid.New().String(),
		Scopes:           "read",
		GrantTypes:       "urn:ietf:params:oauth:grant-type:device_code",
		EnableDeviceFlow: true,
		Status:           models.ClientStatusActive,
	}
	require.NoError(t, s.CreateClient(client))

	user := &models.User{
		ID:       uuid.New().String(),
		Username: "device-confirm-user",
		Email:    "device-confirm@example.com",
		IsActive: true,
	}
	require.NoError(t, s.CreateUser(user))

	dc := &models.DeviceCode{
		DeviceCodeHash: "hash-" + uuid.New().String(),
		DeviceCodeSalt: "salt-" + uuid.New().String()[:8],
		DeviceCodeID:   uuid.New().String()[:8],
		UserCode:       strings.ToUpper("ABCD" + uuid.New().String()[:4]),
		ClientID:       client.ClientID,
		Scopes:         "read",
		Resource:       models.StringArray(resource),
		ExpiresAt:      time.Now().Add(30 * time.Minute),
		Interval:       5,
	}
	require.NoError(t, s.CreateDeviceCode(dc))

	r := gin.New()
	r.Use(sessions.Sessions("test_session", cookie.NewStore([]byte("test-secret"))))
	// Auto-populate the session so DeviceVerify sees a logged-in user
	// without round-tripping through /login.
	r.Use(func(c *gin.Context) {
		sess := sessions.Default(c)
		sess.Set(SessionUserID, user.ID)
		_ = sess.Save()
		c.Next()
	})
	r.POST("/device/verify", handler.DeviceVerify)
	return r, s, client, user, dc
}

func postDeviceVerify(t *testing.T, r *gin.Engine, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(
		http.MethodPost,
		"/device/verify",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestDeviceVerify_ResourceBound_FirstPostRendersConfirm asserts the new
// user-consent enforcement point: a resource-bound device code's FIRST POST
// renders the confirm page and MUST NOT authorize. Without this, the
// manual-entry flow would grant tokens for an audience the user never saw.
func TestDeviceVerify_ResourceBound_FirstPostRendersConfirm(t *testing.T) {
	r, s, _, _, dc := setupDeviceVerifyEnv(t, []string{"https://mcp.example.com"})

	w := postDeviceVerify(t, r, url.Values{
		"user_code": {dc.UserCode},
		// no `confirmed=true`
	})

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "https://mcp.example.com",
		"confirm page must show the resource the user is about to grant")

	dcAfter, err := s.GetDeviceCodeByUserCode(dc.UserCode)
	require.NoError(t, err)
	assert.False(t, dcAfter.Authorized,
		"resource-bound device code must NOT be authorized on the first POST")
}

// TestDeviceVerify_ResourceBound_ConfirmedPostAuthorizes asserts the
// completion path: a second POST with `confirmed=true` commits the grant.
func TestDeviceVerify_ResourceBound_ConfirmedPostAuthorizes(t *testing.T) {
	r, s, _, user, dc := setupDeviceVerifyEnv(t, []string{"https://mcp.example.com"})

	w := postDeviceVerify(t, r, url.Values{
		"user_code": {dc.UserCode},
		"confirmed": {"true"},
	})

	require.Equal(t, http.StatusOK, w.Code)
	dcAfter, err := s.GetDeviceCodeByUserCode(dc.UserCode)
	require.NoError(t, err)
	assert.True(t, dcAfter.Authorized,
		"confirmed POST must mark the device code as authorized")
	assert.Equal(t, user.ID, dcAfter.UserID,
		"authorized device code must record the consenting user's id")
}

// TestDeviceVerify_NoResource_SkipsConfirm asserts the confirm step fires
// ONLY for resource-bound device codes. A non-resource-bound code should
// authorize on the first POST (legacy fast path).
func TestDeviceVerify_NoResource_SkipsConfirm(t *testing.T) {
	r, s, _, _, dc := setupDeviceVerifyEnv(t, nil)

	w := postDeviceVerify(t, r, url.Values{
		"user_code": {dc.UserCode},
	})

	require.Equal(t, http.StatusOK, w.Code)
	dcAfter, err := s.GetDeviceCodeByUserCode(dc.UserCode)
	require.NoError(t, err)
	assert.True(t, dcAfter.Authorized,
		"non-resource-bound device code should authorize on the first POST")
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
