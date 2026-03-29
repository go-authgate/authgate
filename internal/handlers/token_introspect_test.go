package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
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

// ─── Test infrastructure ─────────────────────────────────────────────────────

func setupIntrospectTestEnv(t *testing.T) (*gin.Engine, *store.Store, *services.TokenService) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		JWTExpiration:                    1 * time.Hour,
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		JWTSecret:                        "test-secret-32-chars-long!!!!!!!",
		BaseURL:                          "http://localhost:8080",
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	localProvider, err := token.NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	auditSvc := services.NewNoopAuditService()
	deviceSvc := services.NewDeviceService(s, cfg, auditSvc, metrics.NewNoopMetrics())
	tokenSvc := services.NewTokenService(
		s, cfg, deviceSvc, localProvider, auditSvc, metrics.NewNoopMetrics(),
		cache.NewNoopCache[models.AccessToken](),
	)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, tokenSvc)
	handler := NewTokenHandler(tokenSvc, authzSvc, cfg)

	r := gin.New()
	r.POST("/oauth/token", handler.Token)
	r.POST("/oauth/introspect", handler.Introspect)

	return r, s, tokenSvc
}

// createIntrospectClient creates a confidential client and returns the model + plaintext secret.
func createIntrospectClient(
	t *testing.T,
	s *store.Store,
) (*models.OAuthApplication, string) {
	t.Helper()
	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "Introspect Test Client",
		UserID:                      uuid.New().String(),
		Scopes:                      "read write",
		GrantTypes:                  "client_credentials",
		ClientType:                  core.ClientTypeConfidential.String(),
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
	}
	plainSecret, err := client.GenerateClientSecret(context.Background())
	require.NoError(t, err)
	require.NoError(t, s.CreateClient(client))
	return client, plainSecret
}

// issueTestToken issues a client credentials token and returns the raw access token string.
func issueTestToken(
	t *testing.T,
	r *gin.Engine,
	clientID, clientSecret string,
) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequest(http.MethodPost, "/oauth/token", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	creds := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp["access_token"].(string)
}

// postIntrospect sends a POST /oauth/introspect request.
func postIntrospect(
	t *testing.T,
	r *gin.Engine,
	formValues url.Values,
	basicAuth *[2]string,
) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(formValues.Encode())
	req, err := http.NewRequest(http.MethodPost, "/oauth/introspect", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth != nil {
		creds := base64.StdEncoding.EncodeToString([]byte(basicAuth[0] + ":" + basicAuth[1]))
		req.Header.Set("Authorization", "Basic "+creds)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── Success: active token via HTTP Basic Auth ───────────────────────────────

func TestIntrospect_ActiveToken_BasicAuth(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, secret := createIntrospectClient(t, s)

	accessToken := issueTestToken(t, r, client.ClientID, secret)

	w := postIntrospect(t, r, url.Values{
		"token": {accessToken},
	}, &[2]string{client.ClientID, secret})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, true, resp["active"])
	assert.Equal(t, "read write", resp["scope"])
	assert.Equal(t, client.ClientID, resp["client_id"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Equal(t, "http://localhost:8080", resp["iss"])
	assert.NotEmpty(t, resp["exp"])
	assert.NotEmpty(t, resp["iat"])
	assert.NotEmpty(t, resp["sub"])
	assert.NotEmpty(t, resp["jti"])
}

// ─── Success: active token via form-body credentials ─────────────────────────

func TestIntrospect_ActiveToken_FormBody(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, secret := createIntrospectClient(t, s)

	accessToken := issueTestToken(t, r, client.ClientID, secret)

	w := postIntrospect(t, r, url.Values{
		"token":         {accessToken},
		"client_id":     {client.ClientID},
		"client_secret": {secret},
	}, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["active"])
}

// ─── Inactive: invalid/unknown token ─────────────────────────────────────────

func TestIntrospect_InvalidToken_ReturnsInactive(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, secret := createIntrospectClient(t, s)

	w := postIntrospect(t, r, url.Values{
		"token": {"not-a-real-token"},
	}, &[2]string{client.ClientID, secret})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, false, resp["active"])
	// RFC 7662 §2.2: inactive response MUST only contain "active": false
	assert.Len(t, resp, 1, "inactive response should only contain 'active' field")
}

// ─── Inactive: revoked token ─────────────────────────────────────────────────

func TestIntrospect_RevokedToken_ReturnsInactive(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, secret := createIntrospectClient(t, s)

	accessToken := issueTestToken(t, r, client.ClientID, secret)

	// Revoke the token via the store
	tok, err := s.GetAccessTokenByHash(util.SHA256Hex(accessToken))
	require.NoError(t, err)
	require.NoError(t, s.RevokeToken(tok.ID))

	w := postIntrospect(t, r, url.Values{
		"token": {accessToken},
	}, &[2]string{client.ClientID, secret})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, false, resp["active"])
}

// ─── Error: missing client credentials ───────────────────────────────────────

func TestIntrospect_MissingClientCredentials(t *testing.T) {
	r, _, _ := setupIntrospectTestEnv(t)

	w := postIntrospect(t, r, url.Values{
		"token": {"some-token"},
	}, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client", resp["error"])
	assert.NotEmpty(t, w.Header().Get("WWW-Authenticate"))
}

// ─── Error: wrong client secret ──────────────────────────────────────────────

func TestIntrospect_WrongClientSecret(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, _ := createIntrospectClient(t, s)

	w := postIntrospect(t, r, url.Values{
		"token": {"some-token"},
	}, &[2]string{client.ClientID, "wrong-secret"})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client", resp["error"])
}

// ─── Error: missing token parameter ──────────────────────────────────────────

func TestIntrospect_MissingTokenParameter(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, secret := createIntrospectClient(t, s)

	w := postIntrospect(t, r, url.Values{}, &[2]string{client.ClientID, secret})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_request", resp["error"])
}

// ─── Cross-client introspection: any authenticated client can introspect ─────

func TestIntrospect_CrossClient(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)

	// Client A issues the token
	clientA, secretA := createIntrospectClient(t, s)
	accessToken := issueTestToken(t, r, clientA.ClientID, secretA)

	// Client B introspects it
	clientB, secretB := createIntrospectClient(t, s)
	w := postIntrospect(t, r, url.Values{
		"token": {accessToken},
	}, &[2]string{clientB.ClientID, secretB})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	// Token is active even when introspected by a different client
	assert.Equal(t, true, resp["active"])
	assert.Equal(t, clientA.ClientID, resp["client_id"])
}

// ─── User-delegated token: includes username field ───────────────────────────

func TestIntrospect_UserToken_IncludesUsername(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, secret := createIntrospectClient(t, s)

	// Create a test user
	testUser := &models.User{
		ID:       uuid.New().String(),
		Username: "testuser",
		Email:    "test@example.com",
		Role:     models.UserRoleUser,
	}
	require.NoError(t, s.DB().Create(testUser).Error)

	// Manually create a user-delegated token in the DB
	localProvider, err := token.NewLocalTokenProvider(&config.Config{
		JWTExpiration: 1 * time.Hour,
		JWTSecret:     "test-secret-32-chars-long!!!!!!!",
		BaseURL:       "http://localhost:8080",
	})
	require.NoError(t, err)
	tokenResult, err := localProvider.GenerateToken(
		context.Background(), testUser.ID, client.ClientID, "read",
	)
	require.NoError(t, err)

	userToken := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(tokenResult.TokenString),
		RawToken:      tokenResult.TokenString,
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        testUser.ID,
		ClientID:      client.ClientID,
		Scopes:        "read",
		ExpiresAt:     tokenResult.ExpiresAt,
	}
	require.NoError(t, s.DB().Create(userToken).Error)

	// Introspect
	w := postIntrospect(t, r, url.Values{
		"token": {tokenResult.TokenString},
	}, &[2]string{client.ClientID, secret})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["active"])
	assert.Equal(t, "testuser", resp["username"])
	assert.Equal(t, testUser.ID, resp["sub"])
}

// ─── token_type_hint is accepted but optional ────────────────────────────────

func TestIntrospect_TokenTypeHint_Accepted(t *testing.T) {
	r, s, _ := setupIntrospectTestEnv(t)
	client, secret := createIntrospectClient(t, s)

	accessToken := issueTestToken(t, r, client.ClientID, secret)

	w := postIntrospect(t, r, url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}, &[2]string{client.ClientID, secret})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["active"])
}
