package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/util"
)

func jwkSetJSON(t *testing.T, keys []util.JWK) string {
	t.Helper()
	b, err := json.Marshal(util.JWKSet{Keys: keys})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return string(b)
}

func rsaJWKFixture(t *testing.T, kid string) (util.JWK, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return util.JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}, priv
}

func TestJWKSFetcher_CacheHit(t *testing.T) {
	jwk, _ := rsaJWKFixture(t, "k1")
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(jwkSetJSON(t, []util.JWK{jwk})))
	}))
	defer srv.Close()

	mc := cache.NewMemoryCache[util.JWKSet](0)
	defer mc.Close()
	f := NewJWKSFetcher(mc, 2*time.Second, time.Minute)

	ctx := context.Background()
	if _, err := f.Get(ctx, srv.URL); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := f.Get(ctx, srv.URL); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("expected 1 HTTP hit (cache should serve the second), got %d", n)
	}
}

func TestJWKSFetcher_RefreshOnKidMiss(t *testing.T) {
	oldJWK, _ := rsaJWKFixture(t, "old")
	newJWK, _ := rsaJWKFixture(t, "new")
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			_, _ = w.Write([]byte(jwkSetJSON(t, []util.JWK{oldJWK})))
			return
		}
		_, _ = w.Write([]byte(jwkSetJSON(t, []util.JWK{newJWK})))
	}))
	defer srv.Close()

	mc := cache.NewMemoryCache[util.JWKSet](0)
	defer mc.Close()
	f := NewJWKSFetcher(mc, 2*time.Second, time.Minute)

	ctx := context.Background()
	// Warm cache with the old JWKS.
	if _, err := f.Get(ctx, srv.URL); err != nil {
		t.Fatalf("warm: %v", err)
	}
	// Ask for a kid that exists only in the refreshed set — fetcher must refetch.
	set, err := f.GetWithRefresh(ctx, srv.URL, "new")
	if err != nil {
		t.Fatalf("GetWithRefresh: %v", err)
	}
	if got := set.FindByKid("new"); got == nil {
		t.Fatal("expected refresh to find new kid")
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("expected 2 HTTP hits after kid miss, got %d", n)
	}
}

func TestJWKSFetcher_RefreshCooldown(t *testing.T) {
	jwk, _ := rsaJWKFixture(t, "registered")
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(jwkSetJSON(t, []util.JWK{jwk})))
	}))
	defer srv.Close()

	mc := cache.NewMemoryCache[util.JWKSet](0)
	defer mc.Close()
	f := NewJWKSFetcher(mc, 2*time.Second, time.Minute)

	ctx := context.Background()
	// First unknown-kid request triggers a refetch (cache miss forces one more).
	_, err := f.GetWithRefresh(ctx, srv.URL, "unknown")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	firstHits := atomic.LoadInt32(&hits)
	// Second unknown-kid request within the cooldown must NOT refetch.
	_, err = f.GetWithRefresh(ctx, srv.URL, "still-unknown")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != firstHits {
		t.Fatalf("expected no additional refetch within cooldown; hits went %d → %d",
			firstHits, got)
	}
}

func TestJWKSFetcher_Non200Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mc := cache.NewMemoryCache[util.JWKSet](0)
	defer mc.Close()
	f := NewJWKSFetcher(mc, 2*time.Second, time.Minute)
	_, err := f.Get(context.Background(), srv.URL)
	if !errors.Is(err, ErrJWKSFetchFailed) {
		t.Fatalf("expected ErrJWKSFetchFailed, got %v", err)
	}
}

func TestJWKSFetcher_InvalidBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	mc := cache.NewMemoryCache[util.JWKSet](0)
	defer mc.Close()
	f := NewJWKSFetcher(mc, 2*time.Second, time.Minute)
	_, err := f.Get(context.Background(), srv.URL)
	if !errors.Is(err, ErrJWKSFetchFailed) {
		t.Fatalf("expected ErrJWKSFetchFailed, got %v", err)
	}
}

func TestJWKSFetcher_BodyTooLarge(t *testing.T) {
	large := strings.Repeat("a", jwksMaxBodyBytes+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(large))
	}))
	defer srv.Close()

	mc := cache.NewMemoryCache[util.JWKSet](0)
	defer mc.Close()
	f := NewJWKSFetcher(mc, 2*time.Second, time.Minute)
	_, err := f.Get(context.Background(), srv.URL)
	if !errors.Is(err, ErrJWKSTooLarge) {
		t.Fatalf("expected ErrJWKSTooLarge, got %v", err)
	}
}
