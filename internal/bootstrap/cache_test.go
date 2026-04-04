package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
)

func TestInitializeCache_WithInstrumentation(t *testing.T) {
	cfg := &config.Config{
		MetricsEnabled:   true,
		CacheInitTimeout: 5 * time.Second,
	}

	ctx := context.Background()
	c, closeFunc, err := initializeCache[int64](ctx, cfg, cacheOpts{
		cacheType: config.CacheTypeMemory,
		cacheName: "test_with",
		keyPrefix: "authgate:test:",
		label:     "Test",
	})
	if err != nil {
		t.Fatalf("Failed to initialize cache: %v", err)
	}
	defer closeFunc()

	// Verify the returned cache is an InstrumentedCache (wrapping happened)
	if _, ok := c.(*cache.InstrumentedCache[int64]); !ok {
		t.Errorf("Expected *InstrumentedCache, got %T", c)
	}

	// Verify it still works
	_ = c.Set(ctx, "key1", int64(42), time.Minute)
	value, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 42 {
		t.Errorf("Expected 42, got %d", value)
	}
}

func TestInitializeCache_NoInstrumentation(t *testing.T) {
	cfg := &config.Config{
		MetricsEnabled:   false,
		CacheInitTimeout: 5 * time.Second,
	}

	ctx := context.Background()
	c, closeFunc, err := initializeCache[int64](ctx, cfg, cacheOpts{
		cacheType: config.CacheTypeMemory,
		cacheName: "test_without",
		keyPrefix: "authgate:test:",
		label:     "Test",
	})
	if err != nil {
		t.Fatalf("Failed to initialize cache: %v", err)
	}
	defer closeFunc()

	// Verify the returned cache is NOT instrumented
	if _, ok := c.(*cache.InstrumentedCache[int64]); ok {
		t.Error("Expected raw MemoryCache, got InstrumentedCache")
	}

	_ = c.Set(ctx, "key1", int64(42), time.Minute)
	value, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 42 {
		t.Errorf("Expected 42, got %d", value)
	}
}

func TestInitializeTokenCache_Disabled(t *testing.T) {
	cfg := &config.Config{
		MetricsEnabled:    true,
		TokenCacheEnabled: false,
		CacheInitTimeout:  5 * time.Second,
	}

	ctx := context.Background()
	c, closeFunc, err := initializeTokenCache(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to initialize token cache: %v", err)
	}
	defer closeFunc()

	// Disabled token cache returns a NoopCache — not wrapped since we removed
	// the pointless instrumentation of noop (it would only show 100% miss rate)
	if c == nil {
		t.Fatal("Expected non-nil cache")
	}

	// NoopCache always returns cache miss
	_, err = c.Get(ctx, "key1")
	if err == nil {
		t.Error("Expected cache miss from NoopCache, got nil error")
	}
}

func TestInitializeAllCaches(t *testing.T) {
	cfg := &config.Config{
		MetricsEnabled:            true,
		MetricsGaugeUpdateEnabled: true,
		TokenCacheEnabled:         true,
		CacheInitTimeout:          5 * time.Second,

		TokenCacheType:              config.CacheTypeMemory,
		TokenCacheClientTTL:         time.Hour,
		TokenCacheSizePerConn:       32,
		ClientCacheType:             config.CacheTypeMemory,
		ClientCacheClientTTL:        30 * time.Second,
		ClientCacheSizePerConn:      32,
		UserCacheType:               config.CacheTypeMemory,
		UserCacheClientTTL:          30 * time.Second,
		UserCacheSizePerConn:        32,
		MetricsCacheType:            config.CacheTypeMemory,
		MetricsCacheClientTTL:       30 * time.Second,
		MetricsCacheSizePerConn:     32,
		ClientCountCacheType:        config.CacheTypeMemory,
		ClientCountCacheClientTTL:   10 * time.Minute,
		ClientCountCacheSizePerConn: 32,
	}

	ctx := context.Background()

	closers := make([]func() error, 0)
	addCloser := func(f func() error) {
		if f != nil {
			closers = append(closers, f)
		}
	}
	defer func() {
		for _, f := range closers {
			_ = f()
		}
	}()

	tc, f, err := initializeTokenCache(ctx, cfg)
	if err != nil {
		t.Fatalf("token cache: %v", err)
	}
	addCloser(f)
	_ = tc // different type, just verify no error

	cc, f, err := initializeClientCache(ctx, cfg)
	if err != nil {
		t.Fatalf("client cache: %v", err)
	}
	addCloser(f)
	_ = cc

	uc, f, err := initializeUserCache(ctx, cfg)
	if err != nil {
		t.Fatalf("user cache: %v", err)
	}
	addCloser(f)
	_ = uc

	mc, f, err := initializeMetricsCache(ctx, cfg)
	if err != nil {
		t.Fatalf("metrics cache: %v", err)
	}
	addCloser(f)
	_ = mc

	ccc, f, err := initializeClientCountCache(ctx, cfg)
	if err != nil {
		t.Fatalf("client count cache: %v", err)
	}
	addCloser(f)

	// Sanity check: client count cache should work
	_ = ccc.Set(ctx, "count1", int64(5), time.Minute)
	value, err := ccc.Get(ctx, "count1")
	if err != nil {
		t.Errorf("Expected value from client count cache, got error: %v", err)
	}
	if value != 5 {
		t.Errorf("Expected 5, got %d", value)
	}
}

func TestInitializeCache_MemoryType(t *testing.T) {
	for _, tc := range []struct {
		name           string
		metricsEnabled bool
	}{
		{"with metrics", true},
		{"without metrics", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				MetricsEnabled:   tc.metricsEnabled,
				CacheInitTimeout: 5 * time.Second,
			}

			ctx := context.Background()
			c, closeFunc, err := initializeCache[int64](ctx, cfg, cacheOpts{
				cacheType: config.CacheTypeMemory,
				cacheName: "test_mem",
				keyPrefix: "authgate:test:",
				label:     "Test",
			})
			if err != nil {
				t.Fatalf("Failed to initialize cache: %v", err)
			}
			defer closeFunc()

			_ = c.Set(ctx, "key", int64(123), time.Minute)
			value, err := c.Get(ctx, "key")
			if err != nil {
				t.Fatalf("Expected value, got error: %v", err)
			}
			if value != 123 {
				t.Errorf("Expected 123, got %d", value)
			}
		})
	}
}
