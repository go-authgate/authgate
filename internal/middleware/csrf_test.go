package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupCSRFRouter() *gin.Engine {
	r := setupTestRouter()
	r.Use(CSRFMiddleware())

	r.GET("/form", func(c *gin.Context) {
		c.String(http.StatusOK, "token=%s", GetCSRFToken(c))
	})
	r.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	return r
}

// getCSRFTokenFromGET performs a GET to /form and extracts the CSRF token + cookies.
func getCSRFTokenFromGET(t *testing.T, r *gin.Engine) (string, []*http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/form", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	token := strings.TrimPrefix(body, "token=")
	require.NotEmpty(t, token, "CSRF token should be generated on GET")

	return token, w.Result().Cookies()
}

func TestCSRF_GET_GeneratesToken(t *testing.T) {
	r := setupCSRFRouter()

	token, _ := getCSRFTokenFromGET(t, r)
	assert.NotEmpty(t, token)
}

func TestCSRF_POST_ValidToken(t *testing.T) {
	r := setupCSRFRouter()

	token, cookies := getCSRFTokenFromGET(t, r)

	// POST with valid token in form field
	form := url.Values{csrfFormField: {token}}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestCSRF_POST_MissingToken(t *testing.T) {
	r := setupCSRFRouter()

	_, cookies := getCSRFTokenFromGET(t, r)

	// POST without token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/submit", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_WrongToken(t *testing.T) {
	r := setupCSRFRouter()

	_, cookies := getCSRFTokenFromGET(t, r)

	// POST with wrong token
	form := url.Values{csrfFormField: {"wrong-token"}}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_POST_TokenInHeader(t *testing.T) {
	r := setupCSRFRouter()

	token, cookies := getCSRFTokenFromGET(t, r)

	// POST with token in X-CSRF-Token header
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set(csrfHeaderField, token)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_GET_DoesNotValidate(t *testing.T) {
	r := setupCSRFRouter()

	// GET requests should pass without token validation
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/form", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetCSRFToken_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// No CSRF token set in context
	token := GetCSRFToken(c)
	assert.Empty(t, token)
}

func TestGetCSRFToken_NonString(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(csrfTokenKey, 12345) // wrong type

	token := GetCSRFToken(c)
	assert.Empty(t, token)
}

func TestCSRF_TokenPersistsAcrossRequests(t *testing.T) {
	r := setupCSRFRouter()

	// First request generates token
	token1, cookies := getCSRFTokenFromGET(t, r)

	// Second request with same session should return same token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/form", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	r.ServeHTTP(w, req)

	token2 := strings.TrimPrefix(w.Body.String(), "token=")
	assert.Equal(t, token1, token2, "CSRF token should persist in session")
}

func TestCSRF_PUT_DELETE_PATCH_Validated(t *testing.T) {
	r := setupCSRFRouter()

	// Add routes for PUT/DELETE/PATCH
	r.PUT("/submit", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.DELETE("/submit", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.PATCH("/submit", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	_, cookies := getCSRFTokenFromGET(t, r)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(method, "/submit", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code, "method %s should require CSRF token", method)
	}
}

func TestGenerateCSRFToken(t *testing.T) {
	token := generateCSRFToken()
	assert.NotEmpty(t, token)
	assert.Greater(t, len(token), 20, "token should be a base64-encoded 32 bytes")

	// Tokens should be unique
	token2 := generateCSRFToken()
	assert.NotEqual(t, token, token2)
}

func TestCSRF_POST_WithoutSession(t *testing.T) {
	// POST to a route with CSRF middleware but no prior GET (no session yet)
	r := setupCSRFRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/submit", nil)
	r.ServeHTTP(w, req)

	// Should fail — new session generates token, but POST has no submitted token
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_SessionSaveBehavior(t *testing.T) {
	r := setupCSRFRouter()

	// First GET — should set session cookie
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/form", nil)
	r.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	foundSession := false
	for _, c := range cookies {
		if c.Name == "test_session" {
			foundSession = true
		}
	}
	assert.True(t, foundSession, "Session cookie should be set after first GET")
}

func TestCSRF_ConcurrentDifferentSessions(t *testing.T) {
	r := setupCSRFRouter()

	// Two independent sessions should get different tokens
	token1, _ := getCSRFTokenFromGET(t, r)
	token2, _ := getCSRFTokenFromGET(t, r)

	// Each new session (no cookies) should generate a unique token
	assert.NotEqual(t, token1, token2)
}
