package bootstrap

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata
var testdataFS embed.FS

// testStaticFS returns an fs.FS rooted at the static directory,
// mirroring what serveStaticFilesFromFS expects.
func testStaticFS(t *testing.T) fs.FS {
	t.Helper()
	sub, err := fs.Sub(testdataFS, "testdata/internal/templates/static")
	require.NoError(t, err)
	return sub
}

func setupStaticRouter(t *testing.T, cacheMaxAge time.Duration) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	serveStaticFilesFromFS(r, testStaticFS(t), cacheMaxAge)
	return r
}

func TestStaticCacheControl_DistFilesGetImmutable(t *testing.T) {
	r := setupStaticRouter(t, 24*time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/dist/main-62KIAYER.css", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
}

func TestStaticCacheControl_NonDistFilesGetConfiguredMaxAge(t *testing.T) {
	r := setupStaticRouter(t, 24*time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/images/favicon.ico", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=86400", w.Header().Get("Cache-Control"))
}

func TestStaticCacheControl_ZeroMaxAgeDisablesCacheForNonDist(t *testing.T) {
	r := setupStaticRouter(t, 0)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/images/favicon.ico", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Cache-Control"))
}

func TestStaticCacheControl_ZeroMaxAgeStillCachesDist(t *testing.T) {
	r := setupStaticRouter(t, 0)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/dist/main-62KIAYER.css", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
}

func TestStaticCacheControl_CustomMaxAge(t *testing.T) {
	r := setupStaticRouter(t, 48*time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/images/favicon.ico", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, fmt.Sprintf("public, max-age=%d", 48*60*60), w.Header().Get("Cache-Control"))
}

func TestStaticCacheControl_404HasNoCacheHeader(t *testing.T) {
	r := setupStaticRouter(t, 24*time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/nonexistent.txt", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Empty(t, w.Header().Get("Cache-Control"))
}

func TestStaticCacheControl_HeadRequest(t *testing.T) {
	r := setupStaticRouter(t, 24*time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/static/dist/main-62KIAYER.css", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Body.String(), "HEAD response should have no body")
}

func TestStaticCacheControl_HeadNonDistFile(t *testing.T) {
	r := setupStaticRouter(t, 24*time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/static/images/favicon.ico", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=86400", w.Header().Get("Cache-Control"))
}

func TestFaviconCacheControl(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	faviconData, err := testdataFS.ReadFile("testdata/internal/templates/static/images/favicon.ico")
	require.NoError(t, err)

	r.GET("/favicon.ico", createFaviconHandlerFromBytes(faviconData, 24*time.Hour))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=86400", w.Header().Get("Cache-Control"))
}

func TestFaviconCacheControl_ZeroDisables(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	faviconData, err := testdataFS.ReadFile("testdata/internal/templates/static/images/favicon.ico")
	require.NoError(t, err)

	r.GET("/favicon.ico", createFaviconHandlerFromBytes(faviconData, 0))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Cache-Control"))
}
