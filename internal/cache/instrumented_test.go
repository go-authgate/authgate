package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestInstrumentedCache_Get_Hit(t *testing.T) {
	cacheName := "test_get_hit"
	// Setup: Create underlying memory cache and pre-populate
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ctx := context.Background()
	_ = underlying.Set(ctx, "key1", int64(42), time.Minute)

	// Wrap with instrumentation
	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Get from cache (should be a hit)
	value, err := instrumented.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 42 {
		t.Errorf("Expected value 42, got %d", value)
	}

	// Verify hit counter incremented
	hitCount := testutil.ToFloat64(instrumented.metrics.hits.WithLabelValues(cacheName))
	if hitCount != 1.0 {
		t.Errorf("Expected 1 hit, got %f", hitCount)
	}

	// Verify miss counter did not increment
	missCount := testutil.ToFloat64(instrumented.metrics.misses.WithLabelValues(cacheName))
	if missCount != 0.0 {
		t.Errorf("Expected 0 misses, got %f", missCount)
	}
}

func TestInstrumentedCache_Get_Miss(t *testing.T) {
	cacheName := "test_get_miss"
	// Setup: Create empty cache
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Get from cache (should be a miss)
	ctx := context.Background()
	value, err := instrumented.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Expected ErrCacheMiss, got %v", err)
	}
	if value != 0 {
		t.Errorf("Expected zero value, got %d", value)
	}

	// Verify miss counter incremented
	missCount := testutil.ToFloat64(instrumented.metrics.misses.WithLabelValues(cacheName))
	if missCount != 1.0 {
		t.Errorf("Expected 1 miss, got %f", missCount)
	}

	// Verify hit counter did not increment
	hitCount := testutil.ToFloat64(instrumented.metrics.hits.WithLabelValues(cacheName))
	if hitCount != 0.0 {
		t.Errorf("Expected 0 hits, got %f", hitCount)
	}
}

func TestInstrumentedCache_Get_Error(t *testing.T) {
	cacheName := "test_get_error"
	// Setup: Create a mock cache that returns an error
	mockErr := errors.New("mock error")
	mockCache := &mockCache[int64]{
		getFunc: func(ctx context.Context, key string) (int64, error) {
			return 0, mockErr
		},
	}

	instrumented := NewInstrumentedCache[int64](mockCache, cacheName)

	// Get from cache (should be an error)
	ctx := context.Background()
	_, err := instrumented.Get(ctx, "key")
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	// Verify error counter incremented
	errorCount := testutil.ToFloat64(instrumented.metrics.errors.WithLabelValues(cacheName, "get"))
	if errorCount != 1.0 {
		t.Errorf("Expected 1 error, got %f", errorCount)
	}

	// Verify hit/miss counters did not increment
	hitCount := testutil.ToFloat64(instrumented.metrics.hits.WithLabelValues(cacheName))
	if hitCount != 0.0 {
		t.Errorf("Expected 0 hits, got %f", hitCount)
	}
	missCount := testutil.ToFloat64(instrumented.metrics.misses.WithLabelValues(cacheName))
	if missCount != 0.0 {
		t.Errorf("Expected 0 misses, got %f", missCount)
	}
}

func TestInstrumentedCache_GetWithFetch_Hit(t *testing.T) {
	cacheName := "test_gwf_hit"
	// Setup: Create cache and pre-populate
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ctx := context.Background()
	_ = underlying.Set(ctx, "key1", int64(42), time.Minute)

	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Track if fetchFunc was called
	fetchCalled := false
	fetchFunc := func(ctx context.Context, key string) (int64, error) {
		fetchCalled = true
		return 100, nil
	}

	// GetWithFetch (should hit cache, not call fetchFunc)
	value, err := instrumented.GetWithFetch(ctx, "key1", time.Minute, fetchFunc)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 42 {
		t.Errorf("Expected cached value 42, got %d", value)
	}
	if fetchCalled {
		t.Error("fetchFunc should not have been called on cache hit")
	}

	// Verify hit counter incremented
	hitCount := testutil.ToFloat64(instrumented.metrics.hits.WithLabelValues(cacheName))
	if hitCount != 1.0 {
		t.Errorf("Expected 1 hit, got %f", hitCount)
	}

	// Verify miss counter did not increment
	missCount := testutil.ToFloat64(instrumented.metrics.misses.WithLabelValues(cacheName))
	if missCount != 0.0 {
		t.Errorf("Expected 0 misses, got %f", missCount)
	}
}

func TestInstrumentedCache_GetWithFetch_Miss(t *testing.T) {
	cacheName := "test_gwf_miss"
	// Setup: Create empty cache
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Track if fetchFunc was called
	fetchCalled := false
	fetchFunc := func(ctx context.Context, key string) (int64, error) {
		fetchCalled = true
		return 100, nil
	}

	// GetWithFetch (should miss cache, call fetchFunc)
	ctx := context.Background()
	value, err := instrumented.GetWithFetch(ctx, "key1", time.Minute, fetchFunc)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 100 {
		t.Errorf("Expected fetched value 100, got %d", value)
	}
	if !fetchCalled {
		t.Error("fetchFunc should have been called on cache miss")
	}

	// Verify miss counter incremented
	missCount := testutil.ToFloat64(instrumented.metrics.misses.WithLabelValues(cacheName))
	if missCount != 1.0 {
		t.Errorf("Expected 1 miss, got %f", missCount)
	}

	// Verify hit counter did not increment
	hitCount := testutil.ToFloat64(instrumented.metrics.hits.WithLabelValues(cacheName))
	if hitCount != 0.0 {
		t.Errorf("Expected 0 hits, got %f", hitCount)
	}
}

func TestInstrumentedCache_GetWithFetch_FetchError(t *testing.T) {
	cacheName := "test_gwf_error"
	// Setup: Create empty cache
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	instrumented := NewInstrumentedCache(underlying, cacheName)

	// fetchFunc that returns an error
	fetchErr := errors.New("fetch failed")
	fetchFunc := func(ctx context.Context, key string) (int64, error) {
		return 0, fetchErr
	}

	// GetWithFetch (should miss cache, fetchFunc fails)
	ctx := context.Background()
	_, err := instrumented.GetWithFetch(ctx, "key1", time.Minute, fetchFunc)
	if !errors.Is(err, fetchErr) {
		t.Fatalf("Expected fetch error, got %v", err)
	}

	// Verify miss counter incremented (cache miss occurred)
	missCount := testutil.ToFloat64(instrumented.metrics.misses.WithLabelValues(cacheName))
	if missCount != 1.0 {
		t.Errorf("Expected 1 miss, got %f", missCount)
	}

	// Note: fetchFunc error is not recorded as cache error
	// (it's an application error, not a cache infrastructure error)
}

func TestInstrumentedCache_Set(t *testing.T) {
	cacheName := "test_set"
	// Setup
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Set value
	ctx := context.Background()
	err := instrumented.Set(ctx, "key1", int64(42), time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify value was set in underlying cache
	value, err := underlying.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Expected value in cache, got error: %v", err)
	}
	if value != 42 {
		t.Errorf("Expected value 42, got %d", value)
	}
}

func TestInstrumentedCache_Set_Error(t *testing.T) {
	cacheName := "test_set_error"
	// Setup: Mock cache that returns error on Set
	mockErr := errors.New("set failed")
	mockCache := &mockCache[int64]{
		setFunc: func(ctx context.Context, key string, value int64, ttl time.Duration) error {
			return mockErr
		},
	}

	instrumented := NewInstrumentedCache[int64](mockCache, cacheName)

	// Set value (should fail)
	ctx := context.Background()
	err := instrumented.Set(ctx, "key1", int64(42), time.Minute)
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	// Verify error counter incremented
	errorCount := testutil.ToFloat64(instrumented.metrics.errors.WithLabelValues(cacheName, "set"))
	if errorCount != 1.0 {
		t.Errorf("Expected 1 error, got %f", errorCount)
	}
}

func TestInstrumentedCache_Delete(t *testing.T) {
	cacheName := "test_delete"
	// Setup
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ctx := context.Background()
	_ = underlying.Set(ctx, "key1", int64(42), time.Minute)

	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Delete value
	err := instrumented.Delete(ctx, "key1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify value was deleted
	_, err = underlying.Get(ctx, "key1")
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Expected ErrCacheMiss after delete, got %v", err)
	}
}

func TestInstrumentedCache_Delete_Error(t *testing.T) {
	cacheName := "test_delete_error"
	// Setup: Mock cache that returns error on Delete
	mockErr := errors.New("delete failed")
	mockCache := &mockCache[int64]{
		deleteFunc: func(ctx context.Context, key string) error {
			return mockErr
		},
	}

	instrumented := NewInstrumentedCache[int64](mockCache, cacheName)

	// Delete value (should fail)
	ctx := context.Background()
	err := instrumented.Delete(ctx, "key1")
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	// Verify error counter incremented
	errorCount := testutil.ToFloat64(
		instrumented.metrics.errors.WithLabelValues(cacheName, "delete"),
	)
	if errorCount != 1.0 {
		t.Errorf("Expected 1 error, got %f", errorCount)
	}
}

func TestInstrumentedCache_Health(t *testing.T) {
	cacheName := "test_health"
	// Setup
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Health check
	ctx := context.Background()
	err := instrumented.Health(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestInstrumentedCache_Health_Error(t *testing.T) {
	cacheName := "test_health_error"
	// Setup: Mock cache that returns error on Health
	mockErr := errors.New("health check failed")
	mockCache := &mockCache[int64]{
		healthFunc: func(ctx context.Context) error {
			return mockErr
		},
	}

	instrumented := NewInstrumentedCache[int64](mockCache, cacheName)

	// Health check (should fail)
	ctx := context.Background()
	err := instrumented.Health(ctx)
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	// Verify error counter incremented
	errorCount := testutil.ToFloat64(
		instrumented.metrics.errors.WithLabelValues(cacheName, "health"),
	)
	if errorCount != 1.0 {
		t.Errorf("Expected 1 error, got %f", errorCount)
	}
}

func TestInstrumentedCache_MultipleCaches(t *testing.T) {
	// Setup: Create two instrumented caches with different names
	cache1 := NewInstrumentedCache(NewMemoryCache[int64](), "cache1")
	cache2 := NewInstrumentedCache(NewMemoryCache[int64](), "cache2")
	t.Cleanup(func() {
		_ = cache1.Close()
		_ = cache2.Close()
	})

	ctx := context.Background()

	// Generate hits on cache1
	_ = cache1.Set(ctx, "key", int64(1), time.Minute)
	_, _ = cache1.Get(ctx, "key")

	// Generate misses on cache2
	_, _ = cache2.Get(ctx, "nonexistent")

	// Verify metrics are tracked separately
	cache1Hits := testutil.ToFloat64(cache1.metrics.hits.WithLabelValues("cache1"))
	if cache1Hits != 1.0 {
		t.Errorf("Expected 1 hit for cache1, got %f", cache1Hits)
	}

	cache2Hits := testutil.ToFloat64(cache2.metrics.hits.WithLabelValues("cache2"))
	if cache2Hits != 0.0 {
		t.Errorf("Expected 0 hits for cache2, got %f", cache2Hits)
	}

	cache1Misses := testutil.ToFloat64(cache1.metrics.misses.WithLabelValues("cache1"))
	if cache1Misses != 0.0 {
		t.Errorf("Expected 0 misses for cache1, got %f", cache1Misses)
	}

	cache2Misses := testutil.ToFloat64(cache2.metrics.misses.WithLabelValues("cache2"))
	if cache2Misses != 1.0 {
		t.Errorf("Expected 1 miss for cache2, got %f", cache2Misses)
	}
}

func TestInstrumentedCache_Close(t *testing.T) {
	cacheName := "test_close"
	// Setup
	underlying := NewMemoryCache[int64]()
	instrumented := NewInstrumentedCache(underlying, cacheName)

	// Close should pass through to underlying cache
	err := instrumented.Close()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestCacheMetrics_Registration(t *testing.T) {
	// Verify that metrics are registered only once (via sync.Once)
	// Multiple calls to getCacheMetrics should return the same instance
	m1 := getCacheMetrics()
	m2 := getCacheMetrics()

	if m1 != m2 {
		t.Error("Expected getCacheMetrics to return the same instance")
	}
}

// mockCache is a test helper that implements core.Cache[T] with configurable behavior
type mockCache[T any] struct {
	getFunc          func(ctx context.Context, key string) (T, error)
	setFunc          func(ctx context.Context, key string, value T, ttl time.Duration) error
	deleteFunc       func(ctx context.Context, key string) error
	closeFunc        func() error
	healthFunc       func(ctx context.Context) error
	getWithFetchFunc func(ctx context.Context, key string, ttl time.Duration, fetchFunc func(ctx context.Context, key string) (T, error)) (T, error)
}

func (m *mockCache[T]) Get(ctx context.Context, key string) (T, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, key)
	}
	var zero T
	return zero, ErrCacheMiss
}

func (m *mockCache[T]) Set(ctx context.Context, key string, value T, ttl time.Duration) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, key, value, ttl)
	}
	return nil
}

func (m *mockCache[T]) Delete(ctx context.Context, key string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, key)
	}
	return nil
}

func (m *mockCache[T]) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockCache[T]) Health(ctx context.Context) error {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return nil
}

func (m *mockCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	if m.getWithFetchFunc != nil {
		return m.getWithFetchFunc(ctx, key, ttl, fetchFunc)
	}
	// Default: delegate to Get, and if miss, call fetchFunc
	value, err := m.Get(ctx, key)
	if err == nil {
		return value, nil
	}
	return fetchFunc(ctx, key)
}
