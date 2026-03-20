package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	jwksTestRSAKey  *rsa.PrivateKey
	jwksTestRSAOnce sync.Once
	jwksTestECKey   *ecdsa.PrivateKey
	jwksTestECOnce  sync.Once
)

func getJWKSTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	jwksTestRSAOnce.Do(func() {
		var err error
		jwksTestRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("failed to generate test RSA key: " + err.Error())
		}
	})
	return jwksTestRSAKey
}

func getJWKSTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	jwksTestECOnce.Do(func() {
		var err error
		jwksTestECKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic("failed to generate test EC key: " + err.Error())
		}
	})
	return jwksTestECKey
}

func TestJWKS_RSA_ReturnsValidJWK(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rsaKey := getJWKSTestRSAKey(t)

	handler := NewJWKSHandler("RS256", "rsa-kid-1", &rsaKey.PublicKey)

	r := gin.New()
	r.GET("/.well-known/jwks.json", handler.JWKS)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp JWKSResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Keys, 1)

	jwk := resp.Keys[0]
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "rsa-kid-1", jwk.Kid)
	assert.Equal(t, "RS256", jwk.Alg)
	assert.NotEmpty(t, jwk.N)
	assert.NotEmpty(t, jwk.E)
	assert.Empty(t, jwk.Crv)
	assert.Empty(t, jwk.X)
	assert.Empty(t, jwk.Y)
}

func TestJWKS_ECDSA_ReturnsValidJWK(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ecKey := getJWKSTestECKey(t)

	handler := NewJWKSHandler("ES256", "ec-kid-1", &ecKey.PublicKey)

	r := gin.New()
	r.GET("/.well-known/jwks.json", handler.JWKS)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp JWKSResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Keys, 1)

	jwk := resp.Keys[0]
	assert.Equal(t, "EC", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "ec-kid-1", jwk.Kid)
	assert.Equal(t, "ES256", jwk.Alg)
	assert.Equal(t, "P-256", jwk.Crv)
	assert.NotEmpty(t, jwk.X)
	assert.NotEmpty(t, jwk.Y)
	assert.Empty(t, jwk.N)
	assert.Empty(t, jwk.E)
}

func TestJWKS_HS256_ReturnsEmptyKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// HS256: nil public key → empty keys
	handler := NewJWKSHandler("HS256", "", nil)

	r := gin.New()
	r.GET("/.well-known/jwks.json", handler.JWKS)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp JWKSResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Keys)
}

func TestJWKS_EC_CoordinatesPadded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ecKey := getJWKSTestECKey(t)

	handler := NewJWKSHandler("ES256", "pad-test", &ecKey.PublicKey)

	r := gin.New()
	r.GET("/.well-known/jwks.json", handler.JWKS)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp JWKSResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Keys, 1)

	// P-256 coordinates should decode to exactly 32 bytes each
	// base64url of 32 bytes = 43 chars
	assert.Len(t, resp.Keys[0].X, 43, "X coordinate should be 43 base64url chars (32 bytes)")
	assert.Len(t, resp.Keys[0].Y, 43, "Y coordinate should be 43 base64url chars (32 bytes)")
}

func TestJWKS_Keys_ReturnsCopy(t *testing.T) {
	rsaKey := getJWKSTestRSAKey(t)

	handler := NewJWKSHandler("RS256", "kid1", &rsaKey.PublicKey)

	// Mutate the slice returned by Keys()
	keys1 := handler.Keys()
	require.Len(t, keys1, 1)
	keys1[0].Kid = "mutated"

	// A second call must return the original, unmodified data
	keys2 := handler.Keys()
	require.Len(t, keys2, 1)
	assert.Equal(
		t,
		"kid1",
		keys2[0].Kid,
		"Keys() must return a copy; mutation must not affect internal state",
	)
}
