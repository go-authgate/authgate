package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
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
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupPKJWTEnv builds a test router whose /oauth/token endpoint accepts RFC 7523
// client_assertion in addition to the classic client_secret paths.
func setupPKJWTEnv(t *testing.T) (*gin.Engine, *store.Store, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	baseURL := "https://authgate.test"
	cfg := &config.Config{
		BaseURL:                          baseURL,
		JWTExpiration:                    time.Hour,
		ClientCredentialsTokenExpiration: time.Hour,
		JWTSecret:                        "test-secret-32-chars-long!!!!!!!",
		PrivateKeyJWTEnabled:             true,
		JWKSFetchTimeout:                 2 * time.Second,
		JWKSCacheTTL:                     time.Minute,
		ClientAssertionMaxLifetime:       5 * time.Minute,
		ClientAssertionClockSkew:         30 * time.Second,
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	localProvider, err := token.NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	auditSvc := services.NewNoopAuditService()
	clientSvc := services.NewClientService(s, auditSvc, nil, 0, nil, 0)
	deviceSvc := services.NewDeviceService(s, cfg, auditSvc, metrics.NewNoopMetrics(), clientSvc)
	tokenSvc := services.NewTokenService(
		s, cfg, deviceSvc, localProvider, auditSvc, metrics.NewNoopMetrics(),
		cache.NewNoopCache[models.AccessToken](), clientSvc,
	)
	authzSvc := services.NewAuthorizationService(s, cfg, auditSvc, tokenSvc, clientSvc)

	jwksCache := cache.NewMemoryCache[util.JWKSet](0)
	jtiCache := cache.NewMemoryCache[bool](0)
	t.Cleanup(func() {
		_ = jwksCache.Close()
		_ = jtiCache.Close()
	})
	fetcher := services.NewJWKSFetcher(jwksCache, cfg.JWKSFetchTimeout, cfg.JWKSCacheTTL)
	tokenEndpoint := strings.TrimRight(baseURL, "/") + "/oauth/token"
	verifier := services.NewClientAssertionVerifier(
		clientSvc, fetcher, jtiCache, auditSvc,
		services.ClientAssertionConfig{
			Enabled:           true,
			ExpectedAudiences: []string{tokenEndpoint, baseURL},
			MaxLifetime:       cfg.ClientAssertionMaxLifetime,
			ClockSkew:         cfg.ClientAssertionClockSkew,
		},
	)
	clientAuth := NewClientAuthenticator(clientSvc, verifier)
	handler := NewTokenHandler(tokenSvc, authzSvc, cfg).WithClientAuthenticator(clientAuth)

	r := gin.New()
	r.POST("/oauth/token", handler.Token)
	r.POST("/oauth/introspect", handler.Introspect)

	return r, s, tokenEndpoint
}

// seedPKJWTClient inserts a confidential client whose token endpoint auth method
// is private_key_jwt with the given inline JWK Set.
func seedPKJWTClient(
	t *testing.T,
	s *store.Store,
	jwk util.JWK,
	alg string,
) *models.OAuthApplication {
	t.Helper()
	blob, err := json.Marshal(util.JWKSet{Keys: []util.JWK{jwk}})
	require.NoError(t, err)
	client := &models.OAuthApplication{
		ClientID:                    uuid.New().String(),
		ClientName:                  "MCP M2M client",
		UserID:                      uuid.New().String(),
		Scopes:                      "read write",
		GrantTypes:                  "client_credentials",
		ClientType:                  core.ClientTypeConfidential.String(),
		EnableClientCredentialsFlow: true,
		Status:                      models.ClientStatusActive,
		TokenEndpointAuthMethod:     models.TokenEndpointAuthPrivateKeyJWT,
		TokenEndpointAuthSigningAlg: alg,
		JWKS:                        string(blob),
	}
	require.NoError(t, s.CreateClient(client))
	return client
}

func rsaPKJWTFixture(t *testing.T, kid string) (*rsa.PrivateKey, util.JWK) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, util.JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
}

func signAssertion(
	t *testing.T,
	priv *rsa.PrivateKey,
	kid, clientID, audience string,
) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": uuid.NewString(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	out, err := tok.SignedString(priv)
	require.NoError(t, err)
	return out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestPrivateKeyJWT_ClientCredentials_Success(t *testing.T) {
	r, s, aud := setupPKJWTEnv(t)
	priv, jwk := rsaPKJWTFixture(t, "k1")
	client := seedPKJWTClient(t, s, jwk, "RS256")

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {services.AssertionType},
		"client_assertion":      {signAssertion(t, priv, "k1", client.ClientID, aud)},
		"scope":                 {"read"},
	}
	w := postToken(t, r, form, nil)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotEmpty(t, resp["access_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Equal(t, "read", resp["scope"])
	// RFC 6749 §4.4.3 — no refresh_token
	_, hasRefresh := resp["refresh_token"]
	assert.False(t, hasRefresh)
}

func TestPrivateKeyJWT_ClientCredentials_InvalidAud(t *testing.T) {
	r, s, _ := setupPKJWTEnv(t)
	priv, jwk := rsaPKJWTFixture(t, "k1")
	client := seedPKJWTClient(t, s, jwk, "RS256")

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {services.AssertionType},
		"client_assertion": {
			signAssertion(t, priv, "k1", client.ClientID, "https://attacker.example"),
		},
	}
	w := postToken(t, r, form, nil)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestPrivateKeyJWT_ClientCredentials_ReplayRejected(t *testing.T) {
	r, s, aud := setupPKJWTEnv(t)
	priv, jwk := rsaPKJWTFixture(t, "k1")
	client := seedPKJWTClient(t, s, jwk, "RS256")

	assertion := signAssertion(t, priv, "k1", client.ClientID, aud)
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {services.AssertionType},
		"client_assertion":      {assertion},
	}
	// First use succeeds
	w := postToken(t, r, form, nil)
	require.Equal(t, http.StatusOK, w.Code, "first call body=%s", w.Body.String())
	// Second use of the exact same assertion must be rejected as replay.
	w2 := postToken(t, r, form, nil)
	require.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestPrivateKeyJWT_Introspect_Success(t *testing.T) {
	r, s, aud := setupPKJWTEnv(t)
	priv, jwk := rsaPKJWTFixture(t, "k1")
	client := seedPKJWTClient(t, s, jwk, "RS256")

	// First obtain an access token via client_credentials.
	ccForm := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {services.AssertionType},
		"client_assertion":      {signAssertion(t, priv, "k1", client.ClientID, aud)},
	}
	w := postToken(t, r, ccForm, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&tokenResp))
	accessToken := tokenResp["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Now introspect it, authenticating via a fresh assertion.
	introForm := url.Values{
		"token":                 {accessToken},
		"client_assertion_type": {services.AssertionType},
		"client_assertion":      {signAssertion(t, priv, "k1", client.ClientID, aud)},
	}
	req, err := http.NewRequest(
		http.MethodPost,
		"/oauth/introspect",
		strings.NewReader(introForm.Encode()),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var introResp map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&introResp))
	assert.Equal(t, true, introResp["active"])
	assert.Equal(t, client.ClientID, introResp["client_id"])
}

func TestPrivateKeyJWT_DisabledMethodRejectsSecretAttempt(t *testing.T) {
	r, s, _ := setupPKJWTEnv(t)
	_, jwk := rsaPKJWTFixture(t, "k1")
	client := seedPKJWTClient(t, s, jwk, "RS256")

	// Attempt to authenticate a private_key_jwt client with a shared secret.
	// The client has no secret hash stored, so this must be rejected.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {"anything"},
	}
	w := postToken(t, r, form, nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}
