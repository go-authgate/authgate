package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildWellKnownRouter mirrors the router setup in setupAllRoutes for the
// /.well-known/* group only, so CORS behaviour can be asserted in isolation
// without booting the full bootstrap pipeline.
func buildWellKnownRouter(cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	wellKnown := r.Group("/.well-known")
	if cfg.CORSEnabled {
		wellKnown.Use(middleware.CORSMiddleware(cfg))
	}
	stub := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) }
	preflight := func(c *gin.Context) {}
	for _, path := range []string{
		"/openid-configuration",
		"/oauth-authorization-server",
		"/jwks.json",
	} {
		wellKnown.OPTIONS(path, preflight)
	}
	wellKnown.GET("/openid-configuration", stub)
	wellKnown.GET("/oauth-authorization-server", stub)
	wellKnown.GET("/jwks.json", stub)
	return r
}

func TestWellKnown_CORS_AllowsConfiguredOrigin(t *testing.T) {
	cfg := &config.Config{
		CORSEnabled:        true,
		CORSAllowedOrigins: []string{"https://allowed.example.com"},
		CORSAllowedMethods: []string{"GET", "OPTIONS"},
		CORSAllowedHeaders: []string{"Origin", "Content-Type"},
	}
	r := buildWellKnownRouter(cfg)

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/oauth-authorization-server",
		nil,
	)
	req.Header.Set("Origin", "https://allowed.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(
		t,
		"https://allowed.example.com",
		w.Header().Get("Access-Control-Allow-Origin"),
	)
}

func TestWellKnown_CORS_RejectsUnconfiguredOrigin(t *testing.T) {
	cfg := &config.Config{
		CORSEnabled:        true,
		CORSAllowedOrigins: []string{"https://allowed.example.com"},
		CORSAllowedMethods: []string{"GET", "OPTIONS"},
		CORSAllowedHeaders: []string{"Origin", "Content-Type"},
	}
	r := buildWellKnownRouter(cfg)

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/oauth-authorization-server",
		nil,
	)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// gin-contrib/cors rejects un-allowed origins; ACAO must be empty so the
	// browser refuses to expose the response to JS.
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestWellKnown_CORS_PreflightOPTIONSAllowed(t *testing.T) {
	cfg := &config.Config{
		CORSEnabled:        true,
		CORSAllowedOrigins: []string{"https://allowed.example.com"},
		CORSAllowedMethods: []string{"GET", "OPTIONS"},
		CORSAllowedHeaders: []string{"Origin", "Content-Type"},
	}
	r := buildWellKnownRouter(cfg)

	req := httptest.NewRequest(
		http.MethodOptions,
		"/.well-known/oauth-authorization-server",
		nil,
	)
	req.Header.Set("Origin", "https://allowed.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// gin-contrib/cors returns 204 No Content on a successful preflight; the
	// key invariant is that ACAO matches and the response is not 4xx.
	assert.Less(t, w.Code, http.StatusBadRequest,
		"preflight should not return 4xx; got %d", w.Code)
	assert.Equal(
		t,
		"https://allowed.example.com",
		w.Header().Get("Access-Control-Allow-Origin"),
	)
}

func TestWellKnown_CORSDisabled_NoACAOHeader(t *testing.T) {
	cfg := &config.Config{CORSEnabled: false}
	r := buildWellKnownRouter(cfg)

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/oauth-authorization-server",
		nil,
	)
	req.Header.Set("Origin", "https://anything.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(
		t,
		w.Header().Get("Access-Control-Allow-Origin"),
		"CORS disabled must not emit Access-Control-Allow-Origin",
	)
}
