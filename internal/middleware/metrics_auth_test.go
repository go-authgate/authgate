package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	testToken = "test-secret-token-123"
)

func TestMetricsAuthMiddleware_NoAuthConfigured(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MetricsAuthMiddleware(""))
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "metrics")
	})

	// Test: Should allow access without auth when no token configured
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "metrics", w.Body.String())
}

func TestMetricsAuthMiddleware_ValidToken(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	token := testToken
	r := gin.New()
	r.Use(MetricsAuthMiddleware(token))
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "metrics")
	})

	// Test: Valid Bearer token should allow access
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "metrics", w.Body.String())
}

func TestMetricsAuthMiddleware_InvalidToken(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	token := testToken
	r := gin.New()
	r.Use(MetricsAuthMiddleware(token))
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "metrics")
	})

	// Test: Wrong token should be rejected
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid token")
	assert.Equal(t, `Bearer realm="Metrics"`, w.Header().Get("WWW-Authenticate"))
}

func TestMetricsAuthMiddleware_NoAuthProvided(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	token := testToken
	r := gin.New()
	r.Use(MetricsAuthMiddleware(token))
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "metrics")
	})

	// Test: Missing auth header should be rejected
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Bearer token required")
	assert.Equal(t, `Bearer realm="Metrics"`, w.Header().Get("WWW-Authenticate"))
}

func TestMetricsAuthMiddleware_WrongAuthScheme(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	token := testToken
	r := gin.New()
	r.Use(MetricsAuthMiddleware(token))
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "metrics")
	})

	// Test: Basic auth when Bearer is expected should be rejected
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Bearer token required")
}

func TestMetricsAuthMiddleware_EmptyToken(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	token := testToken
	r := gin.New()
	r.Use(MetricsAuthMiddleware(token))
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "metrics")
	})

	// Test: Empty Bearer token should be rejected
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer ")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid token")
}
