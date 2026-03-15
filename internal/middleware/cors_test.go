package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupCORSRouter(cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware(cfg))
	r.GET("/oauth/tokeninfo", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	r.POST("/oauth/token", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	r.OPTIONS("/oauth/token", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func defaultCORSConfig() *config.Config {
	return &config.Config{
		CORSEnabled:        true,
		CORSAllowedOrigins: []string{"http://localhost:3000"},
		CORSAllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		CORSAllowedHeaders: []string{"Origin", "Content-Type", "Authorization"},
		CORSMaxAge:         12 * time.Hour,
	}
}

func TestCORS_AllowedOrigin(t *testing.T) {
	r := setupCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/tokeninfo", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	r := setupCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/tokeninfo", nil)
	req.Header.Set("Origin", "http://evil.com")
	r.ServeHTTP(w, req)

	// gin-contrib/cors returns 403 for disallowed origins
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_PreflightRequest(t *testing.T) {
	r := setupCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/oauth/token", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type,Authorization")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	assert.NotEmpty(t, w.Header().Get("Access-Control-Max-Age"))
}

func TestCORS_PreflightDisallowedOrigin(t *testing.T) {
	r := setupCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/oauth/token", nil)
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	r.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_MultipleOrigins(t *testing.T) {
	cfg := defaultCORSConfig()
	cfg.CORSAllowedOrigins = []string{"http://localhost:3000", "https://app.example.com"}
	r := setupCORSRouter(cfg)

	// First origin
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/tokeninfo", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	r.ServeHTTP(w, req)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))

	// Second origin
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/oauth/tokeninfo", nil)
	req.Header.Set("Origin", "https://app.example.com")
	r.ServeHTTP(w, req)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoOriginHeader(t *testing.T) {
	r := setupCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/tokeninfo", nil)
	// No Origin header — same-origin request
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_ExposeHeaders(t *testing.T) {
	r := setupCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/tokeninfo", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	r.ServeHTTP(w, req)

	exposed := w.Header().Get("Access-Control-Expose-Headers")
	assert.Contains(t, exposed, "Content-Length")
	assert.Contains(t, exposed, "Content-Type")
}

func TestCORS_POSTWithOrigin(t *testing.T) {
	r := setupCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestNewCORSConfig(t *testing.T) {
	cfg := NewCORSConfig(
		[]string{"http://localhost:3000"},
		[]string{"GET", "POST"},
		[]string{"Authorization"},
		1*time.Hour,
	)

	assert.Equal(t, []string{"http://localhost:3000"}, cfg.AllowOrigins)
	assert.Equal(t, []string{"GET", "POST"}, cfg.AllowMethods)
	assert.Equal(t, []string{"Authorization"}, cfg.AllowHeaders)
	assert.Equal(t, 1*time.Hour, cfg.MaxAge)
	assert.True(t, cfg.AllowCredentials)
}
