package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/metrics"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestOAuthHandler creates an OAuthHandler with a fake GitHub provider and no-op metrics.
func newTestOAuthHandler(baseURL string) *OAuthHandler {
	provider := auth.NewGitHubProvider(auth.OAuthProviderConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/oauth/github/callback",
	})
	return NewOAuthHandler(
		map[string]*auth.OAuthProvider{"github": provider},
		nil, // userService not exercised in these tests
		http.DefaultClient,
		baseURL,
		false, // session fingerprint disabled
		false,
		metrics.NewNoopMetrics(),
	)
}

// setupOAuthRouter builds a Gin router with session middleware, the OAuth routes,
// and a /test-session helper that returns current session keys as JSON.
func setupOAuthRouter(h *OAuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	store := cookie.NewStore([]byte("test-secret"))
	r.Use(sessions.Sessions("test_session", store))

	r.GET("/oauth/:provider", h.LoginWithProvider)
	r.GET("/oauth/:provider/callback", h.OAuthCallback)

	// Helper endpoint: exposes session state for assertions.
	r.GET("/test-session", func(c *gin.Context) {
		sess := sessions.Default(c)
		c.JSON(http.StatusOK, gin.H{
			"oauth_redirect": sess.Get("oauth_redirect"),
			"oauth_state":    sess.Get("oauth_state"),
			"oauth_provider": sess.Get("oauth_provider"),
		})
	})

	return r
}

// sessionCookies extracts Set-Cookie headers from a response recorder.
func sessionCookies(w *httptest.ResponseRecorder) []*http.Cookie {
	resp := http.Response{Header: w.Header()}
	return resp.Cookies()
}

// readSession makes a GET /test-session request using the provided cookies
// and returns the decoded JSON body.
func readSession(
	t *testing.T,
	r *gin.Engine,
	cookies []*http.Cookie,
) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/test-session",
		nil,
	)
	require.NoError(t, err)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var data map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &data))
	return data
}

// ============================================================
// LoginWithProvider – redirect validation
// ============================================================

func TestLoginWithProvider_UnknownProvider_Returns400(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/unknown",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLoginWithProvider_NoRedirect_RedirectsToOAuthProvider(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/github", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should redirect to GitHub's OAuth URL
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "github.com")

	// No oauth_redirect should be stored
	sess := readSession(t, r, sessionCookies(w))
	assert.Nil(t, sess["oauth_redirect"])
}

func TestLoginWithProvider_SafeRelativeRedirect_StoredInSession(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github?redirect=/device",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	sess := readSession(t, r, sessionCookies(w))
	assert.Equal(t, "/device", sess["oauth_redirect"])
}

func TestLoginWithProvider_ExternalURLRedirect_RejectedFromSession(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github?redirect=https://attacker.com/phishing",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Still redirects to the OAuth provider (login proceeds normally)
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	// But the malicious redirect must not be stored
	sess := readSession(t, r, sessionCookies(w))
	assert.Nil(t, sess["oauth_redirect"])
}

func TestLoginWithProvider_ProtocolRelativeRedirect_RejectedFromSession(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github?redirect=//evil.com",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	sess := readSession(t, r, sessionCookies(w))
	assert.Nil(t, sess["oauth_redirect"])
}

func TestLoginWithProvider_JavascriptSchemeRedirect_RejectedFromSession(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github?redirect=javascript:alert(1)",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	sess := readSession(t, r, sessionCookies(w))
	assert.Nil(t, sess["oauth_redirect"])
}

func TestLoginWithProvider_AbsoluteURLSameHost_StoredInSession(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github?redirect=http://localhost:8080/device",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	sess := readSession(t, r, sessionCookies(w))
	assert.Equal(t, "http://localhost:8080/device", sess["oauth_redirect"])
}

func TestLoginWithProvider_HeaderInjectionRedirect_RejectedFromSession(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github?redirect=/device%0d%0aSet-Cookie:+evil=1",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	sess := readSession(t, r, sessionCookies(w))
	assert.Nil(t, sess["oauth_redirect"])
}

// ============================================================
// OAuthCallback – early validation (no real OAuth exchange needed)
// ============================================================

func TestOAuthCallback_UnknownProvider_Returns400(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/unknown/callback?code=abc&state=xyz",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuthCallback_StateTooLong_Returns400(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	longState := strings.Repeat("a", maxStateLength+1)
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github/callback?code=abc&state="+longState,
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuthCallback_NoSessionState_Returns400(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	// No prior LoginWithProvider call, so session has no oauth_state
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github/callback?code=abc&state=some-state",
		nil,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuthCallback_StateMismatch_Returns400(t *testing.T) {
	h := newTestOAuthHandler("http://localhost:8080")
	r := setupOAuthRouter(h)

	// Seed the session with a known state via LoginWithProvider
	initReq, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github",
		nil,
	)
	initW := httptest.NewRecorder()
	r.ServeHTTP(initW, initReq)
	require.Equal(t, http.StatusTemporaryRedirect, initW.Code)

	// Call callback with a different (wrong) state
	callbackReq, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/github/callback?code=abc&state=wrong-state",
		nil,
	)
	for _, c := range sessionCookies(initW) {
		callbackReq.AddCookie(c)
	}
	callbackW := httptest.NewRecorder()
	r.ServeHTTP(callbackW, callbackReq)

	assert.Equal(t, http.StatusBadRequest, callbackW.Code)
}
