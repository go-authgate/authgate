package handlers

import (
	"context"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Test infrastructure ─────────────────────────────────────────────────────

func setupCacheTestEnv(t *testing.T) (
	*gin.Engine,
	*store.Store,
	*services.TokenService,
	*cache.MemoryCache[models.AccessToken],
) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		JWTExpiration:                    1 * time.Hour,
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		JWTSecret:                        "test-secret-32-chars-long!!!!!!!",
		BaseURL:                          "http://localhost:8080",
		TokenCacheEnabled:                true,
		TokenCacheTTL:                    5 * time.Minute,
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	memCache := cache.NewMemoryCache[models.AccessToken]()

	localProvider, err := token.NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	auditSvc := services.NewAuditService(s, false, 0)
	clientSvc := services.NewClientService(s, auditSvc, nil, 0, nil, 0)
	deviceSvc := services.NewDeviceService(s, cfg, auditSvc, metrics.NewNoopMetrics(), clientSvc)
	tokenSvc := services.NewTokenService(
		s, cfg, deviceSvc, localProvider, auditSvc, metrics.NewNoopMetrics(), memCache, clientSvc,
	)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, tokenSvc, clientSvc)
	handler := NewTokenHandler(tokenSvc, authzSvc, cfg)

	r := gin.New()
	r.POST("/oauth/token", handler.Token)
	r.GET("/oauth/tokeninfo", handler.TokenInfo)
	r.POST("/oauth/revoke", handler.Revoke)

	return r, s, tokenSvc, memCache
}

// postRevoke sends a POST /oauth/revoke request with the given token.
func postRevoke(
	t *testing.T,
	r *gin.Engine,
	tokenString string,
) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"token": {tokenString}}
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequest(http.MethodPost, "/oauth/revoke", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// issueAndExtractToken creates a CC client, issues a token, and returns the access_token string.
func issueAndExtractToken(
	t *testing.T,
	r *gin.Engine,
	s *store.Store,
) string {
	t.Helper()
	client, plainSecret := createCCClient(t, s, true, core.ClientTypeConfidential)
	form := url.Values{"grant_type": {"client_credentials"}}
	w := postToken(t, r, form, &[2]string{client.ClientID, plainSecret})
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp["access_token"].(string)
}

// ─── Cache population ────────────────────────────────────────────────────────

func TestTokenInfo_CachePopulatedOnFirstCall(t *testing.T) {
	r, s, _, memCache := setupCacheTestEnv(t)
	ctx := context.Background()
	accessToken := issueAndExtractToken(t, r, s)
	hash := util.SHA256Hex(accessToken)

	_, err := memCache.Get(ctx, hash)
	require.Error(t, err, "cache should be empty before first call")

	w := tokenInfoReq(t, r, accessToken)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["active"])

	cached, err := memCache.Get(ctx, hash)
	require.NoError(t, err, "cache should be populated after first call")
	assert.Equal(t, models.TokenStatusActive, cached.Status)

	// Second call hits cache — must still succeed
	w2 := tokenInfoReq(t, r, accessToken)
	assert.Equal(t, http.StatusOK, w2.Code)
}

// ─── Revoke → tokeninfo integration (Issue #133 core requirement) ────────────

func TestTokenInfo_RevokeViaHTTP_InvalidatesCache(t *testing.T) {
	r, s, _, memCache := setupCacheTestEnv(t)
	ctx := context.Background()
	accessToken := issueAndExtractToken(t, r, s)
	hash := util.SHA256Hex(accessToken)

	w := tokenInfoReq(t, r, accessToken)
	require.Equal(t, http.StatusOK, w.Code)
	_, err := memCache.Get(ctx, hash)
	require.NoError(t, err, "cache should be populated")

	w2 := postRevoke(t, r, accessToken)
	assert.Equal(t, http.StatusOK, w2.Code)

	_, err = memCache.Get(ctx, hash)
	require.Error(t, err, "cache should be invalidated after revocation")

	// Immediately re-validate — must be rejected despite prior cache entry
	w3 := tokenInfoReq(t, r, accessToken)
	assert.Equal(t, http.StatusUnauthorized, w3.Code)
	var errResp map[string]any
	require.NoError(t, json.NewDecoder(w3.Body).Decode(&errResp))
	assert.Equal(t, "invalid_token", errResp["error"])
}

// ─── Disable → tokeninfo integration ─────────────────────────────────────────

func TestTokenInfo_DisableToken_InvalidatesCache(t *testing.T) {
	r, s, tokenSvc, memCache := setupCacheTestEnv(t)
	ctx := context.Background()
	accessToken := issueAndExtractToken(t, r, s)
	hash := util.SHA256Hex(accessToken)

	w := tokenInfoReq(t, r, accessToken)
	require.Equal(t, http.StatusOK, w.Code)
	_, err := memCache.Get(ctx, hash)
	require.NoError(t, err)

	tok, err := s.GetAccessTokenByHash(hash)
	require.NoError(t, err)
	err = tokenSvc.DisableToken(ctx, tok.ID, "test-admin")
	require.NoError(t, err)

	_, err = memCache.Get(ctx, hash)
	require.Error(t, err, "cache should be invalidated after disable")

	w2 := tokenInfoReq(t, r, accessToken)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
	var errResp map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&errResp))
	assert.Equal(t, "invalid_token", errResp["error"])
}

// ─── Nil cache regression ────────────────────────────────────────────────────

func TestTokenInfo_NilCache_RevokeStillWorks(t *testing.T) {
	r, s := setupCCTestEnv(t)
	accessToken := issueAndExtractToken(t, r, s)
	hash := util.SHA256Hex(accessToken)

	w := tokenInfoReq(t, r, accessToken)
	require.Equal(t, http.StatusOK, w.Code)

	// Revoke directly via store — setupCCTestEnv has no /oauth/revoke route
	tok, err := s.GetAccessTokenByHash(hash)
	require.NoError(t, err)
	err = s.RevokeToken(tok.ID)
	require.NoError(t, err)

	w2 := tokenInfoReq(t, r, accessToken)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
	var errResp map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&errResp))
	assert.Equal(t, "invalid_token", errResp["error"])
}
