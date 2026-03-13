package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Test infrastructure ─────────────────────────────────────────────────────

func setupRegistrationTestEnv(t *testing.T, enableRegistration bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		JWTExpiration:                   1 * time.Hour,
		JWTSecret:                       "test-secret-32-chars-long!!!!!!!",
		BaseURL:                         "http://localhost:8080",
		EnableDynamicClientRegistration: enableRegistration,
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	auditSvc := services.NewAuditService(s, false, 0)
	clientSvc := services.NewClientService(s, auditSvc, nil, 0)
	handler := NewRegistrationHandler(clientSvc, auditSvc, cfg)

	r := gin.New()
	r.POST("/oauth/register", handler.Register)

	return r
}

// postRegister sends a POST /oauth/register request with JSON body.
func postRegister(
	t *testing.T,
	r *gin.Engine,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── Success: minimal registration (authorization_code default) ──────────────

func TestRegister_Success_Minimal(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":   "My App",
		"redirect_uris": []string{"https://example.com/callback"},
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.NotEmpty(t, resp["client_id"])
	assert.NotEmpty(t, resp["client_secret"])
	assert.Equal(t, "My App", resp["client_name"])
	assert.InDelta(t, 0, resp["client_secret_expires_at"], 0)
	assert.NotNil(t, resp["client_id_issued_at"])

	// Default grant type should be authorization_code
	grantTypes, ok := resp["grant_types"].([]any)
	require.True(t, ok)
	assert.Contains(t, grantTypes, "authorization_code")

	// RFC 7591 §2: default token_endpoint_auth_method is "client_secret_basic"
	assert.Equal(t, "client_secret_basic", resp["token_endpoint_auth_method"])
}

// ─── Success: device code grant type ─────────────────────────────────────────

func TestRegister_Success_DeviceCodeGrant(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name": "CLI Tool",
		"grant_types": []string{"urn:ietf:params:oauth:grant-type:device_code"},
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	grantTypes, ok := resp["grant_types"].([]any)
	require.True(t, ok)
	assert.Contains(t, grantTypes, "urn:ietf:params:oauth:grant-type:device_code")
}

// ─── Success: confidential client ────────────────────────────────────────────

func TestRegister_Success_ConfidentialClient(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":                "Web App",
		"redirect_uris":              []string{"https://example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "client_secret_basic",
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, "client_secret_basic", resp["token_endpoint_auth_method"])
	assert.NotEmpty(t, resp["client_secret"])
}

// ─── Success: client_secret_post echoed back ─────────────────────────────────

func TestRegister_Success_ClientSecretPost(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":                "Post Auth App",
		"redirect_uris":              []string{"https://example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "client_secret_post",
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	// Should echo back the requested method, not hardcode client_secret_basic
	assert.Equal(t, "client_secret_post", resp["token_endpoint_auth_method"])
	assert.NotEmpty(t, resp["client_secret"])
}

// ─── Success: explicit public client (none) ─────────────────────────────────

func TestRegister_Success_PublicClient(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":                "SPA App",
		"redirect_uris":              []string{"https://example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "none",
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, "none", resp["token_endpoint_auth_method"])
}

// ─── Success: with scopes ────────────────────────────────────────────────────

func TestRegister_Success_WithScopes(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":   "Scoped App",
		"redirect_uris": []string{"https://example.com/callback"},
		"scope":         "openid email profile",
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "openid email profile", resp["scope"])
}

// ─── Success: device_code shorthand ──────────────────────────────────────────

func TestRegister_Success_DeviceCodeShorthand(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name": "CLI",
		"grant_types": []string{"device_code"},
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	grantTypes, ok := resp["grant_types"].([]any)
	require.True(t, ok)
	assert.Contains(t, grantTypes, "urn:ietf:params:oauth:grant-type:device_code")
}

// ─── Error: registration disabled ────────────────────────────────────────────

func TestRegister_Disabled(t *testing.T) {
	r := setupRegistrationTestEnv(t, false)

	w := postRegister(t, r, map[string]any{
		"client_name": "My App",
	})

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "registration_not_supported", resp["error"])
}

// ─── Error: missing client_name ──────────────────────────────────────────────

func TestRegister_MissingClientName(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"redirect_uris": []string{"https://example.com/callback"},
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client_metadata", resp["error"])
}

// ─── Error: unsupported grant_type ───────────────────────────────────────────

func TestRegister_UnsupportedGrantType(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name": "My App",
		"grant_types": []string{"implicit"},
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client_metadata", resp["error"])
	assert.Contains(t, resp["error_description"], "implicit")
}

// ─── Error: unsupported token_endpoint_auth_method ───────────────────────────

func TestRegister_UnsupportedAuthMethod(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":                "My App",
		"token_endpoint_auth_method": "private_key_jwt",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client_metadata", resp["error"])
	assert.Contains(t, resp["error_description"], "private_key_jwt")
}

// ─── Error: unsupported scope ────────────────────────────────────────────────

func TestRegister_UnsupportedScope(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name": "My App",
		"scope":       "admin",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client_metadata", resp["error"])
	assert.Contains(t, resp["error_description"], "admin")
}

// ─── Error: auth_code without redirect_uris ──────────────────────────────────

func TestRegister_AuthCodeWithoutRedirectURIs(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name": "My App",
		"grant_types": []string{"authorization_code"},
		// missing redirect_uris
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client_metadata", resp["error"])
}

// ─── Error: invalid JSON body ────────────────────────────────────────────────

func TestRegister_InvalidJSON(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	req, err := http.NewRequest(http.MethodPost, "/oauth/register",
		bytes.NewReader([]byte("not json")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client_metadata", resp["error"])
}

// ─── Error: invalid redirect URI ─────────────────────────────────────────────

func TestRegister_InvalidRedirectURI(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":   "My App",
		"redirect_uris": []string{"not-a-uri"},
		"grant_types":   []string{"authorization_code"},
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client_metadata", resp["error"])
}

// ─── Multiple grant types ────────────────────────────────────────────────────

func TestRegister_MultipleGrantTypes(t *testing.T) {
	r := setupRegistrationTestEnv(t, true)

	w := postRegister(t, r, map[string]any{
		"client_name":   "Hybrid App",
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"authorization_code", "device_code"},
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	grantTypes, ok := resp["grant_types"].([]any)
	require.True(t, ok)
	assert.Len(t, grantTypes, 2)
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, "urn:ietf:params:oauth:grant-type:device_code")
}
