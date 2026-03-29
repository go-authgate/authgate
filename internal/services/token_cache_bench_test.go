package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/token"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
)

// benchTokenEnv holds the pre-built state shared across benchmark iterations.
type benchTokenEnv struct {
	svc         *TokenService
	tokenString string
}

func newBenchEnv(b *testing.B, withCache bool) *benchTokenEnv {
	b.Helper()

	cfg := &config.Config{
		JWTExpiration:                    1 * time.Hour,
		ClientCredentialsTokenExpiration: 1 * time.Hour,
		JWTSecret:                        "bench-secret-32-chars-long!!!!!!",
		BaseURL:                          "http://localhost:8080",
		TokenCacheEnabled:                withCache,
		TokenCacheTTL:                    5 * time.Minute,
	}

	s, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	if err != nil {
		b.Fatal(err)
	}

	localProvider, err := token.NewLocalTokenProvider(cfg)
	if err != nil {
		b.Fatal(err)
	}
	deviceSvc := NewDeviceService(s, cfg, NewNoopAuditService(), metrics.NewNoopMetrics())

	var tokenCache core.Cache[models.AccessToken]
	if withCache {
		tokenCache = cache.NewMemoryCache[models.AccessToken]()
	} else {
		tokenCache = cache.NewNoopCache[models.AccessToken]()
	}
	svc := NewTokenService(
		s,
		cfg,
		deviceSvc,
		localProvider,
		NewNoopAuditService(),
		metrics.NewNoopMetrics(),
		tokenCache,
	)

	ctx := context.Background()
	result, err := localProvider.GenerateToken(ctx, "bench-user", "bench-client", "read")
	if err != nil {
		b.Fatal(err)
	}

	tok := &models.AccessToken{
		ID:            uuid.New().String(),
		TokenHash:     util.SHA256Hex(result.TokenString),
		TokenType:     "Bearer",
		TokenCategory: models.TokenCategoryAccess,
		Status:        models.TokenStatusActive,
		UserID:        "bench-user",
		ClientID:      "bench-client",
		Scopes:        "read",
		ExpiresAt:     result.ExpiresAt,
	}
	if err := s.CreateAccessToken(tok); err != nil {
		b.Fatal(err)
	}

	// Warm cache if enabled (first call populates it)
	if withCache {
		if _, err := svc.ValidateToken(ctx, result.TokenString); err != nil {
			b.Fatal(err)
		}
	}

	return &benchTokenEnv{
		svc:         svc,
		tokenString: result.TokenString,
	}
}

// BenchmarkValidateToken_NoCache measures ValidateToken hitting SQLite on every call.
func BenchmarkValidateToken_NoCache(b *testing.B) {
	env := newBenchEnv(b, false)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		if _, err := env.svc.ValidateToken(ctx, env.tokenString); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateToken_WithCache measures ValidateToken with memory cache (cache hit path).
func BenchmarkValidateToken_WithCache(b *testing.B) {
	env := newBenchEnv(b, true)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		if _, err := env.svc.ValidateToken(ctx, env.tokenString); err != nil {
			b.Fatal(err)
		}
	}
}
