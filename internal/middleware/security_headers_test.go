package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders_WithHSTS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeaders(true))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff",
		w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY",
		w.Header().Get("X-Frame-Options"))

	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src")
	assert.Contains(t, csp, "cdn.jsdelivr.net")
	assert.Contains(t, csp, "fonts.googleapis.com")
	assert.Contains(t, csp, "fonts.gstatic.com")
	assert.Contains(t, csp, "frame-ancestors 'none'")

	assert.Equal(t, "strict-origin-when-cross-origin",
		w.Header().Get("Referrer-Policy"))
	assert.Contains(t, w.Header().Get("Permissions-Policy"), "camera=()")
	assert.Equal(t, "max-age=31536000; includeSubDomains",
		w.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_WithoutHSTS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeaders(false))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff",
		w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY",
		w.Header().Get("X-Frame-Options"))
	assert.Contains(t,
		w.Header().Get("Content-Security-Policy"), "default-src 'self'")
	assert.Empty(t,
		w.Header().Get("Strict-Transport-Security"),
		"HSTS must not be set for HTTP")
}
