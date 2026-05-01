package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// buildUserInfoClaims
// ============================================================

func TestBuildUserInfoClaims_AllScopes(t *testing.T) {
	updatedAt := time.Unix(1708646400, 0)
	user := &models.User{
		FullName:      "John Doe",
		Username:      "johndoe",
		AvatarURL:     "https://example.com/avatar.jpg",
		Email:         "john@example.com",
		EmailVerified: true,
	}
	user.UpdatedAt = updatedAt
	claims := buildUserInfoClaims(
		"user-123",
		"https://auth.example.com",
		"openid profile email",
		user,
	)

	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "https://auth.example.com", claims["iss"])
	assert.Equal(t, "John Doe", claims["name"])
	assert.Equal(t, "johndoe", claims["preferred_username"])
	assert.Equal(t, "https://example.com/avatar.jpg", claims["picture"])
	assert.Equal(t, int64(1708646400), claims["updated_at"])
	assert.Equal(t, "john@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])
}

func TestBuildUserInfoClaims_OpenIDOnly(t *testing.T) {
	user := &models.User{
		FullName:  "John Doe",
		Username:  "johndoe",
		AvatarURL: "https://example.com/avatar.jpg",
		Email:     "john@example.com",
	}
	claims := buildUserInfoClaims("user-123", "https://auth.example.com", "openid", user)

	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "https://auth.example.com", claims["iss"])
	assert.Nil(t, claims["name"])
	assert.Nil(t, claims["email"])
	assert.Nil(t, claims["picture"])
}

func TestBuildUserInfoClaims_ProfileScopeOnly(t *testing.T) {
	updatedAt := time.Unix(1000000, 0)
	user := &models.User{
		FullName:  "Jane Smith",
		Username:  "janesmith",
		AvatarURL: "",
		Email:     "jane@example.com",
	}
	user.UpdatedAt = updatedAt
	claims := buildUserInfoClaims("user-456", "https://auth.example.com", "profile", user)

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
	user := &models.User{
		FullName:      "Bob Builder",
		Username:      "bob",
		AvatarURL:     "",
		Email:         "bob@example.com",
		EmailVerified: false,
	}
	claims := buildUserInfoClaims("user-789", "https://auth.example.com", "email", user)

	assert.Equal(t, "user-789", claims["sub"])
	assert.Equal(t, "bob@example.com", claims["email"])
	assert.Equal(t, false, claims["email_verified"])
	// No profile claims
	assert.Nil(t, claims["name"])
}

func TestBuildUserInfoClaims_EmailVerifiedMirrorsUserField(t *testing.T) {
	user := &models.User{
		Email:         "carol@example.com",
		EmailVerified: true,
	}
	claims := buildUserInfoClaims("user-901", "https://auth.example.com", "email", user)
	assert.Equal(t, true, claims["email_verified"])
}

func TestBuildUserInfoClaims_NoScopes(t *testing.T) {
	user := &models.User{
		FullName:  "Nobody",
		Username:  "nobody",
		AvatarURL: "",
		Email:     "nobody@example.com",
	}
	claims := buildUserInfoClaims("user-000", "https://auth.example.com", "", user)

	// sub and iss are always present
	assert.Equal(t, "user-000", claims["sub"])
	assert.Equal(t, "https://auth.example.com", claims["iss"])
	assert.Nil(t, claims["name"])
	assert.Nil(t, claims["email"])
}

func TestBuildUserInfoClaims_NoPictureWhenEmpty(t *testing.T) {
	user := &models.User{
		FullName:  "Test User",
		Username:  "testuser",
		AvatarURL: "", // empty avatar
		Email:     "test@example.com",
	}
	claims := buildUserInfoClaims("user-001", "https://auth.example.com", "profile", user)

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
	handler := NewOIDCHandler(nil, nil, cfg, false, true)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))

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
	assert.Contains(t, claims, "jti")
	assert.Contains(t, claims, "auth_time")
	assert.Contains(t, claims, "nonce")
	assert.Contains(t, claims, "at_hash")
	assert.Contains(t, claims, "email_verified")
	assert.Contains(t, claims, "name")
	assert.Contains(t, claims, "preferred_username")
	assert.Contains(t, claims, "picture")
	assert.Contains(t, claims, "updated_at")

	// Per OIDC Discovery 1.0, claims_supported lists claims emitted in ID
	// tokens / UserInfo only. AuthGate's access/refresh JWT claims are
	// documented in docs/JWT_VERIFICATION.md and must not leak in here.
	for _, jwtOnly := range []string{"user_id", "client_id", "scope", "type", "project", "service_account", "domain"} {
		assert.NotContains(
			t,
			claims,
			jwtOnly,
			"claims_supported must only list ID token / UserInfo claims; %q is access/refresh-token-only",
			jwtOnly,
		)
	}
}

// TestDiscovery_OmitsDomainEvenWhenSet asserts the server-attested `domain`
// claim never appears in OIDC `claims_supported`, even after an operator sets
// JWT_DOMAIN. domain is an access/refresh-token-only claim — the same trust
// model as project / service_account — and OIDC discovery must not advertise
// it.
func TestDiscovery_OmitsDomainEvenWhenSet(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{BaseURL: "https://auth.example.com", JWTDomain: "oa"}
	handler := NewOIDCHandler(nil, nil, cfg, false, true)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))

	claims, ok := meta["claims_supported"].([]any)
	require.True(t, ok)
	assert.NotContains(t, claims, "domain",
		"claims_supported must not advertise the access-token-only `domain` claim")
}

func TestDiscovery_StripsTrailingSlashFromBaseURL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{BaseURL: "https://auth.example.com/"}
	handler := NewOIDCHandler(nil, nil, cfg, false, true)

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
	handler := NewOIDCHandler(nil, nil, cfg, false, true)

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
	handler := NewOIDCHandler(nil, nil, cfg, false, true)

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

// ============================================================
// Discovery — JWT signing algorithm and jwks_uri
// ============================================================

func TestDiscovery_RS256_IncludesJwksURI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		BaseURL:             "https://auth.example.com",
		JWTSigningAlgorithm: "RS256",
	}
	handler := NewOIDCHandler(nil, nil, cfg, true, true)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))

	// jwks_uri present for asymmetric algorithms
	assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", meta["jwks_uri"])

	// Algorithm matches config
	algs, ok := meta["id_token_signing_alg_values_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, algs, "RS256")
}

func TestDiscovery_ES256_IncludesJwksURI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		BaseURL:             "https://auth.example.com",
		JWTSigningAlgorithm: "ES256",
	}
	handler := NewOIDCHandler(nil, nil, cfg, true, true)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))

	assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", meta["jwks_uri"])

	algs, ok := meta["id_token_signing_alg_values_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, algs, "ES256")
}

func TestDiscovery_HS256_NoJwksURI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		BaseURL:             "https://auth.example.com",
		JWTSigningAlgorithm: "HS256",
	}
	handler := NewOIDCHandler(nil, nil, cfg, false, true)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))

	// jwks_uri must be absent for HS256
	_, hasJwksURI := meta["jwks_uri"]
	assert.False(t, hasJwksURI, "HS256 should not include jwks_uri")

	algs, ok := meta["id_token_signing_alg_values_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, algs, "HS256")
}

func TestDiscovery_EmptyAlgorithm_DefaultsToHS256(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		BaseURL:             "https://auth.example.com",
		JWTSigningAlgorithm: "", // empty = default HS256
	}
	handler := NewOIDCHandler(nil, nil, cfg, false, true)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discovery)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var meta map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meta))

	// Default to HS256 when empty
	algs, ok := meta["id_token_signing_alg_values_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, algs, "HS256")

	// No jwks_uri for HS256
	_, hasJwksURI := meta["jwks_uri"]
	assert.False(t, hasJwksURI)
}
