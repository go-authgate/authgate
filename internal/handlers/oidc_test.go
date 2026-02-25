package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// parseScopeSet
// ============================================================

func TestParseScopeSet_MultipleScopes(t *testing.T) {
	set := parseScopeSet("openid profile email")
	assert.True(t, set["openid"])
	assert.True(t, set["profile"])
	assert.True(t, set["email"])
	assert.False(t, set["read"])
}

func TestParseScopeSet_Empty(t *testing.T) {
	set := parseScopeSet("")
	assert.Empty(t, set)
}

func TestParseScopeSet_SingleScope(t *testing.T) {
	set := parseScopeSet("openid")
	assert.True(t, set["openid"])
	assert.False(t, set["profile"])
}

// ============================================================
// buildUserInfoClaims
// ============================================================

func TestBuildUserInfoClaims_AllScopes(t *testing.T) {
	updatedAt := time.Unix(1708646400, 0)
	claims := buildUserInfoClaims(
		"user-123",
		"https://auth.example.com",
		"openid profile email",
		"John Doe",
		"johndoe",
		"https://example.com/avatar.jpg",
		"john@example.com",
		updatedAt,
	)

	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "https://auth.example.com", claims["iss"])
	assert.Equal(t, "John Doe", claims["name"])
	assert.Equal(t, "johndoe", claims["preferred_username"])
	assert.Equal(t, "https://example.com/avatar.jpg", claims["picture"])
	assert.Equal(t, int64(1708646400), claims["updated_at"])
	assert.Equal(t, "john@example.com", claims["email"])
	assert.Equal(t, false, claims["email_verified"])
}

func TestBuildUserInfoClaims_OpenIDOnly(t *testing.T) {
	claims := buildUserInfoClaims(
		"user-123",
		"https://auth.example.com",
		"openid",
		"John Doe",
		"johndoe",
		"https://example.com/avatar.jpg",
		"john@example.com",
		time.Now(),
	)

	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "https://auth.example.com", claims["iss"])
	assert.Nil(t, claims["name"])
	assert.Nil(t, claims["email"])
	assert.Nil(t, claims["picture"])
}

func TestBuildUserInfoClaims_ProfileScopeOnly(t *testing.T) {
	updatedAt := time.Unix(1000000, 0)
	claims := buildUserInfoClaims(
		"user-456",
		"https://auth.example.com",
		"profile",
		"Jane Smith",
		"janesmith",
		"",
		"jane@example.com",
		updatedAt,
	)

	assert.Equal(t, "user-456", claims["sub"])
	assert.Equal(t, "Jane Smith", claims["name"])
	assert.Equal(t, "janesmith", claims["preferred_username"])
	assert.Equal(t, int64(1000000), claims["updated_at"])
	// No picture because avatarURL is empty
	assert.Nil(t, claims["picture"])
	// No email because email scope not granted
	assert.Nil(t, claims["email"])
}

func TestBuildUserInfoClaims_EmailScopeOnly(t *testing.T) {
	claims := buildUserInfoClaims(
		"user-789",
		"https://auth.example.com",
		"email",
		"Bob Builder",
		"bob",
		"",
		"bob@example.com",
		time.Now(),
	)

	assert.Equal(t, "user-789", claims["sub"])
	assert.Equal(t, "bob@example.com", claims["email"])
	assert.Equal(t, false, claims["email_verified"])
	// No profile claims
	assert.Nil(t, claims["name"])
}

func TestBuildUserInfoClaims_NoScopes(t *testing.T) {
	claims := buildUserInfoClaims(
		"user-000",
		"https://auth.example.com",
		"",
		"Nobody",
		"nobody",
		"",
		"nobody@example.com",
		time.Now(),
	)

	// sub and iss are always present
	assert.Equal(t, "user-000", claims["sub"])
	assert.Equal(t, "https://auth.example.com", claims["iss"])
	assert.Nil(t, claims["name"])
	assert.Nil(t, claims["email"])
}

func TestBuildUserInfoClaims_NoPictureWhenEmpty(t *testing.T) {
	claims := buildUserInfoClaims(
		"user-001",
		"https://auth.example.com",
		"profile",
		"Test User",
		"testuser",
		"", // empty avatar
		"test@example.com",
		time.Now(),
	)

	// picture key should not be set when avatarURL is empty
	_, hasPicture := claims["picture"]
	assert.False(t, hasPicture)
}

// ============================================================
// OIDCHandler.Discovery (HTTP handler test)
// ============================================================

func TestDiscovery_ReturnsCorrectMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{BaseURL: "https://auth.example.com"}
	handler := NewOIDCHandler(nil, nil, cfg)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))

	assert.Equal(t, "https://auth.example.com", meta["issuer"])
	assert.Equal(t, "https://auth.example.com/oauth/authorize", meta["authorization_endpoint"])
	assert.Equal(t, "https://auth.example.com/oauth/token", meta["token_endpoint"])
	assert.Equal(t, "https://auth.example.com/oauth/userinfo", meta["userinfo_endpoint"])
	assert.Equal(t, "https://auth.example.com/oauth/revoke", meta["revocation_endpoint"])

	// Verify arrays
	responseTypes, ok := meta["response_types_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, responseTypes, "code")

	scopes, ok := meta["scopes_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "profile")
	assert.Contains(t, scopes, "email")

	grantTypes, ok := meta["grant_types_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, GrantTypeDeviceCode)
	assert.Contains(t, grantTypes, GrantTypeRefreshToken)

	codeChallenges, ok := meta["code_challenge_methods_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, codeChallenges, "S256")

	claims, ok := meta["claims_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, claims, "sub")
	assert.Contains(t, claims, "iss")
	assert.Contains(t, claims, "aud")
	assert.Contains(t, claims, "exp")
	assert.Contains(t, claims, "iat")
	assert.Contains(t, claims, "auth_time")
	assert.Contains(t, claims, "nonce")
	assert.Contains(t, claims, "at_hash")
	assert.Contains(t, claims, "email_verified")
}

func TestDiscovery_StripsTrailingSlashFromBaseURL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{BaseURL: "https://auth.example.com/"}
	handler := NewOIDCHandler(nil, nil, cfg)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))

	// Trailing slash on base URL must not produce double-slash in endpoint URLs
	assert.Equal(t, "https://auth.example.com/oauth/token", meta["token_endpoint"])
}

// ============================================================
// OIDCHandler.UserInfo – missing / malformed Authorization header
// ============================================================

func TestUserInfo_NoAuthorizationHeader_Returns401(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{BaseURL: "https://auth.example.com"}
	handler := NewOIDCHandler(nil, nil, cfg)

	r := gin.New()
	r.GET("/oauth/userinfo", handler.UserInfo)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "invalid_token", body["error"])

	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "invalid_token")
}

func TestUserInfo_NonBearerToken_Returns401(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{BaseURL: "https://auth.example.com"}
	handler := NewOIDCHandler(nil, nil, cfg)

	r := gin.New()
	r.GET("/oauth/userinfo", handler.UserInfo)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "invalid_token", body["error"])
}
