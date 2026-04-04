package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestInstrumentedCache_Get_Hit(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ctx := context.Background()
	_ = underlying.Set(ctx, "key1", int64(42), time.Minute)

	ic := NewInstrumentedCache(underlying, "test_get_hit")

	value, err := ic.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 42 {
		t.Errorf("Expected value 42, got %d", value)
	}

	if v := testutil.ToFloat64(ic.hitCounter); v != 1 {
		t.Errorf("Expected 1 hit, got %f", v)
	}
	if v := testutil.ToFloat64(ic.missCounter); v != 0 {
		t.Errorf("Expected 0 misses, got %f", v)
	}
}

func TestInstrumentedCache_Get_Miss(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ic := NewInstrumentedCache(underlying, "test_get_miss")

	ctx := context.Background()
	value, err := ic.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Expected ErrCacheMiss, got %v", err)
	}
	if value != 0 {
		t.Errorf("Expected zero value, got %d", value)
	}

	if v := testutil.ToFloat64(ic.missCounter); v != 1 {
		t.Errorf("Expected 1 miss, got %f", v)
	}
	if v := testutil.ToFloat64(ic.hitCounter); v != 0 {
		t.Errorf("Expected 0 hits, got %f", v)
	}
}

func TestInstrumentedCache_Get_Error(t *testing.T) {
	mockErr := errors.New("mock error")
	mc := &mockCache[int64]{
		getFunc: func(_ context.Context, _ string) (int64, error) {
			return 0, mockErr
		},
	}

	ic := NewInstrumentedCache[int64](mc, "test_get_error")

	ctx := context.Background()
	_, err := ic.Get(ctx, "key")
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	if v := testutil.ToFloat64(ic.errGet); v != 1 {
		t.Errorf("Expected 1 error, got %f", v)
	}
	if v := testutil.ToFloat64(ic.hitCounter); v != 0 {
		t.Errorf("Expected 0 hits, got %f", v)
	}
	if v := testutil.ToFloat64(ic.missCounter); v != 0 {
		t.Errorf("Expected 0 misses, got %f", v)
	}
}

func TestInstrumentedCache_GetWithFetch_Hit(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ctx := context.Background()
	_ = underlying.Set(ctx, "key1", int64(42), time.Minute)

	ic := NewInstrumentedCache(underlying, "test_gwf_hit")

	fetchCalled := false
	fetchFunc := func(_ context.Context, _ string) (int64, error) {
		fetchCalled = true
		return 100, nil
	}

	value, err := ic.GetWithFetch(ctx, "key1", time.Minute, fetchFunc)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 42 {
		t.Errorf("Expected cached value 42, got %d", value)
	}
	if fetchCalled {
		t.Error("fetchFunc should not have been called on cache hit")
	}

	if v := testutil.ToFloat64(ic.hitCounter); v != 1 {
		t.Errorf("Expected 1 hit, got %f", v)
	}
	if v := testutil.ToFloat64(ic.missCounter); v != 0 {
		t.Errorf("Expected 0 misses, got %f", v)
	}
}

func TestInstrumentedCache_GetWithFetch_Miss(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ic := NewInstrumentedCache(underlying, "test_gwf_miss")

	fetchCalled := false
	fetchFunc := func(_ context.Context, _ string) (int64, error) {
		fetchCalled = true
		return 100, nil
	}

	ctx := context.Background()
	value, err := ic.GetWithFetch(ctx, "key1", time.Minute, fetchFunc)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if value != 100 {
		t.Errorf("Expected fetched value 100, got %d", value)
	}
	if !fetchCalled {
		t.Error("fetchFunc should have been called on cache miss")
	}

	if v := testutil.ToFloat64(ic.missCounter); v != 1 {
		t.Errorf("Expected 1 miss, got %f", v)
	}
	if v := testutil.ToFloat64(ic.hitCounter); v != 0 {
		t.Errorf("Expected 0 hits, got %f", v)
	}
}

func TestInstrumentedCache_GetWithFetch_FetchError(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ic := NewInstrumentedCache(underlying, "test_gwf_error")

	fetchErr := errors.New("fetch failed")
	fetchFunc := func(_ context.Context, _ string) (int64, error) {
		return 0, fetchErr
	}

	ctx := context.Background()
	_, err := ic.GetWithFetch(ctx, "key1", time.Minute, fetchFunc)
	if !errors.Is(err, fetchErr) {
		t.Fatalf("Expected fetch error, got %v", err)
	}

	// fetch was called → miss recorded; error also recorded separately
	if v := testutil.ToFloat64(ic.missCounter); v != 1 {
		t.Errorf("Expected 1 miss, got %f", v)
	}
	if v := testutil.ToFloat64(ic.errFetch); v != 1 {
		t.Errorf("Expected 1 fetch error, got %f", v)
	}
}

func TestInstrumentedCache_Set(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ic := NewInstrumentedCache(underlying, "test_set")

	ctx := context.Background()
	if err := ic.Set(ctx, "key1", int64(42), time.Minute); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	value, err := underlying.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Expected value in cache, got error: %v", err)
	}
	if value != 42 {
		t.Errorf("Expected value 42, got %d", value)
	}
}

func TestInstrumentedCache_Set_Error(t *testing.T) {
	mockErr := errors.New("set failed")
	mc := &mockCache[int64]{
		setFunc: func(_ context.Context, _ string, _ int64, _ time.Duration) error {
			return mockErr
		},
	}

	ic := NewInstrumentedCache[int64](mc, "test_set_error")

	ctx := context.Background()
	err := ic.Set(ctx, "key1", int64(42), time.Minute)
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	if v := testutil.ToFloat64(ic.errSet); v != 1 {
		t.Errorf("Expected 1 error, got %f", v)
	}
}

func TestInstrumentedCache_Delete(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ctx := context.Background()
	_ = underlying.Set(ctx, "key1", int64(42), time.Minute)

	ic := NewInstrumentedCache(underlying, "test_delete")

	if err := ic.Delete(ctx, "key1"); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_, err := underlying.Get(ctx, "key1")
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Expected ErrCacheMiss after delete, got %v", err)
	}
}

func TestInstrumentedCache_Delete_Error(t *testing.T) {
	mockErr := errors.New("delete failed")
	mc := &mockCache[int64]{
		deleteFunc: func(_ context.Context, _ string) error {
			return mockErr
		},
	}

	ic := NewInstrumentedCache[int64](mc, "test_delete_error")

	ctx := context.Background()
	err := ic.Delete(ctx, "key1")
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	if v := testutil.ToFloat64(ic.errDelete); v != 1 {
		t.Errorf("Expected 1 error, got %f", v)
	}
}

func TestInstrumentedCache_Health(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	t.Cleanup(func() { _ = underlying.Close() })

	ic := NewInstrumentedCache(underlying, "test_health")

	if err := ic.Health(context.Background()); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestInstrumentedCache_Health_Error(t *testing.T) {
	mockErr := errors.New("health check failed")
	mc := &mockCache[int64]{
		healthFunc: func(_ context.Context) error {
			return mockErr
		},
	}

	ic := NewInstrumentedCache[int64](mc, "test_health_error")

	err := ic.Health(context.Background())
	if !errors.Is(err, mockErr) {
		t.Fatalf("Expected mock error, got %v", err)
	}

	if v := testutil.ToFloat64(ic.errHealth); v != 1 {
		t.Errorf("Expected 1 error, got %f", v)
	}
}

func TestInstrumentedCache_MultipleCaches(t *testing.T) {
	cache1 := NewInstrumentedCache(NewMemoryCache[int64](), "multi_cache1")
	cache2 := NewInstrumentedCache(NewMemoryCache[int64](), "multi_cache2")
	t.Cleanup(func() {
		_ = cache1.Close()
		_ = cache2.Close()
	})

	ctx := context.Background()

	_ = cache1.Set(ctx, "key", int64(1), time.Minute)
	_, _ = cache1.Get(ctx, "key")         // hit on cache1
	_, _ = cache2.Get(ctx, "nonexistent") // miss on cache2

	if v := testutil.ToFloat64(cache1.hitCounter); v != 1 {
		t.Errorf("Expected 1 hit for cache1, got %f", v)
	}
	if v := testutil.ToFloat64(cache2.hitCounter); v != 0 {
		t.Errorf("Expected 0 hits for cache2, got %f", v)
	}
	if v := testutil.ToFloat64(cache1.missCounter); v != 0 {
		t.Errorf("Expected 0 misses for cache1, got %f", v)
	}
	if v := testutil.ToFloat64(cache2.missCounter); v != 1 {
		t.Errorf("Expected 1 miss for cache2, got %f", v)
	}
}

func TestInstrumentedCache_Close(t *testing.T) {
	underlying := NewMemoryCache[int64]()
	ic := NewInstrumentedCache(underlying, "test_close")

	if err := ic.Close(); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestCacheMetrics_Registration(t *testing.T) {
	m1 := getMetrics()
	m2 := getMetrics()
	if m1 != m2 {
		t.Error("Expected getMetrics to return the same instance")
	}
}

// mockCache is a test helper that implements core.Cache[T] with configurable behavior.
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
	value, err := m.Get(ctx, key)
	if err == nil {
		return value, nil
	}
	return fetchFunc(ctx, key)
}
