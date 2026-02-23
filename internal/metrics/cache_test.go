package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
)

// mockStore is a mock implementation of store.Store for testing
type mockStore struct {
	countActiveTokensFunc       func(category string) (int64, error)
	countTotalDeviceCodesFunc   func() (int64, error)
	countPendingDeviceCodesFunc func() (int64, error)
}

func (m *mockStore) CountActiveTokensByCategory(category string) (int64, error) {
	if m.countActiveTokensFunc != nil {
		return m.countActiveTokensFunc(category)
	}
	return 0, nil
}

func (m *mockStore) CountTotalDeviceCodes() (int64, error) {
	if m.countTotalDeviceCodesFunc != nil {
		return m.countTotalDeviceCodesFunc()
	}
	return 0, nil
}

func (m *mockStore) CountPendingDeviceCodes() (int64, error) {
	if m.countPendingDeviceCodesFunc != nil {
		return m.countPendingDeviceCodesFunc()
	}
	return 0, nil
}

// newTestCacheWrapper creates a MetricsCacheWrapper for testing
func newTestCacheWrapper(store *mockStore, cache cache.Cache) *MetricsCacheWrapper {
	return &MetricsCacheWrapper{
		store: store,
		cache: cache,
	}
}

func TestMetricsCacheWrapper_GetActiveTokensCount_CacheHit(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	store := &mockStore{
		countActiveTokensFunc: func(category string) (int64, error) {
			t.Fatal("Should not call store on cache hit")
			return 0, nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	// Pre-populate cache
	_ = memCache.Set(ctx, "tokens:access", 42, time.Minute)

	count, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 42 {
		t.Errorf("Expected count 42, got %d", count)
	}
}

func TestMetricsCacheWrapper_GetActiveTokensCount_CacheMiss(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	dbCalled := false
	store := &mockStore{
		countActiveTokensFunc: func(category string) (int64, error) {
			dbCalled = true
			if category != "access" {
				t.Errorf("Expected category 'access', got '%s'", category)
			}
			return 100, nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	count, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 100 {
		t.Errorf("Expected count 100, got %d", count)
	}

	if !dbCalled {
		t.Error("Expected database to be called on cache miss")
	}

	// Verify cache was updated
	cached, err := memCache.Get(ctx, "tokens:access")
	if err != nil {
		t.Fatalf("Expected cache to be updated, got error: %v", err)
	}

	if cached != 100 {
		t.Errorf("Expected cached value 100, got %d", cached)
	}
}

func TestMetricsCacheWrapper_GetActiveTokensCount_DBError(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	expectedErr := errors.New("database connection failed")
	store := &mockStore{
		countActiveTokensFunc: func(category string) (int64, error) {
			return 0, expectedErr
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	_, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestMetricsCacheWrapper_GetActiveTokensCount_CacheExpiration(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	callCount := 0
	store := &mockStore{
		countActiveTokensFunc: func(category string) (int64, error) {
			callCount++
			return int64(callCount * 10), nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	// First call - cache miss, should query DB
	count1, _ := wrapper.GetActiveTokensCount(ctx, "access", 50*time.Millisecond)
	if count1 != 10 {
		t.Errorf("Expected first count 10, got %d", count1)
	}

	// Second call immediately - cache hit, should not query DB
	count2, _ := wrapper.GetActiveTokensCount(ctx, "access", 50*time.Millisecond)
	if count2 != 10 {
		t.Errorf("Expected second count 10 (cached), got %d", count2)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 DB call, got %d", callCount)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Third call after expiration - cache miss, should query DB again
	count3, _ := wrapper.GetActiveTokensCount(ctx, "access", 50*time.Millisecond)
	if count3 != 20 {
		t.Errorf("Expected third count 20 (new DB query), got %d", count3)
	}

	if callCount != 2 {
		t.Errorf("Expected 2 DB calls after expiration, got %d", callCount)
	}
}

func TestMetricsCacheWrapper_GetTotalDeviceCodesCount_CacheHit(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	store := &mockStore{
		countTotalDeviceCodesFunc: func() (int64, error) {
			t.Fatal("Should not call store on cache hit")
			return 0, nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	// Pre-populate cache
	_ = memCache.Set(ctx, "devices:total", 100, time.Minute)

	count, err := wrapper.GetTotalDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 100 {
		t.Errorf("Expected count 100, got %d", count)
	}
}

func TestMetricsCacheWrapper_GetPendingDeviceCodesCount_CacheHit(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	store := &mockStore{
		countPendingDeviceCodesFunc: func() (int64, error) {
			t.Fatal("Should not call store on cache hit")
			return 0, nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	// Pre-populate cache
	_ = memCache.Set(ctx, "devices:pending", 25, time.Minute)

	count, err := wrapper.GetPendingDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 25 {
		t.Errorf("Expected count 25, got %d", count)
	}
}

func TestMetricsCacheWrapper_GetTotalDeviceCodesCount_CacheMiss(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	dbCalled := false
	store := &mockStore{
		countTotalDeviceCodesFunc: func() (int64, error) {
			dbCalled = true
			return 200, nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	count, err := wrapper.GetTotalDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 200 {
		t.Errorf("Expected count 200, got %d", count)
	}

	if !dbCalled {
		t.Error("Expected database to be called on cache miss")
	}

	// Verify cache was updated
	cached, err := memCache.Get(ctx, "devices:total")
	if err != nil {
		t.Fatalf("Expected cache to be updated, got error: %v", err)
	}

	if cached != 200 {
		t.Errorf("Expected cached value 200, got %d", cached)
	}
}

func TestMetricsCacheWrapper_GetPendingDeviceCodesCount_CacheMiss(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	dbCalled := false
	store := &mockStore{
		countPendingDeviceCodesFunc: func() (int64, error) {
			dbCalled = true
			return 50, nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	count, err := wrapper.GetPendingDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 50 {
		t.Errorf("Expected count 50, got %d", count)
	}

	if !dbCalled {
		t.Error("Expected database to be called on cache miss")
	}

	// Verify cache was updated
	cached, err := memCache.Get(ctx, "devices:pending")
	if err != nil {
		t.Fatalf("Expected cache to be updated, got error: %v", err)
	}

	if cached != 50 {
		t.Errorf("Expected cached value 50, got %d", cached)
	}
}

func TestMetricsCacheWrapper_GetTotalDeviceCodesCount_DBError(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	expectedErr := errors.New("database timeout")
	store := &mockStore{
		countTotalDeviceCodesFunc: func() (int64, error) {
			return 0, expectedErr
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	_, err := wrapper.GetTotalDeviceCodesCount(ctx, time.Minute)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestMetricsCacheWrapper_GetPendingDeviceCodesCount_DBError(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	expectedErr := errors.New("database timeout")
	store := &mockStore{
		countPendingDeviceCodesFunc: func() (int64, error) {
			return 0, expectedErr
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	_, err := wrapper.GetPendingDeviceCodesCount(ctx, time.Minute)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

// mockCacheAside is a mock cache that implements cacheAsideSupport interface
type mockCacheAside struct {
	*cache.MemoryCache
	getWithFetchCalled bool
	fetchFunc          func(ctx context.Context, key string) (int64, error)
}

func (m *mockCacheAside) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (int64, error),
) (int64, error) {
	m.getWithFetchCalled = true
	m.fetchFunc = fetchFunc

	// Check cache first
	if value, err := m.Get(ctx, key); err == nil {
		return value, nil
	}

	// Cache miss - call the fetch function and cache the result
	value, err := fetchFunc(ctx, key)
	if err != nil {
		return 0, err
	}
	_ = m.Set(ctx, key, value, ttl)
	return value, nil
}

func TestMetricsCacheWrapper_UsesGetWithFetch(t *testing.T) {
	ctx := context.Background()
	mockCache := &mockCacheAside{
		MemoryCache: cache.NewMemoryCache(),
	}

	store := &mockStore{
		countActiveTokensFunc: func(category string) (int64, error) {
			return 42, nil
		},
	}

	wrapper := newTestCacheWrapper(store, mockCache)

	count, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 42 {
		t.Errorf("Expected count 42, got %d", count)
	}

	if !mockCache.getWithFetchCalled {
		t.Error("Expected GetWithFetch to be called, but it wasn't")
	}

	// Verify the fetch function works correctly
	if mockCache.fetchFunc != nil {
		val, err := mockCache.fetchFunc(ctx, "test")
		if err != nil {
			t.Errorf("Fetch function returned error: %v", err)
		}
		if val != 42 {
			t.Errorf("Fetch function returned %d, expected 42", val)
		}
	}
}

func TestMetricsCacheWrapper_FallbackToManualCacheAside(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache()

	dbCalled := false
	store := &mockStore{
		countActiveTokensFunc: func(category string) (int64, error) {
			dbCalled = true
			return 100, nil
		},
	}

	wrapper := newTestCacheWrapper(store, memCache)

	count, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 100 {
		t.Errorf("Expected count 100, got %d", count)
	}

	if !dbCalled {
		t.Error("Expected database to be called for cache miss")
	}

	// Verify cache was updated
	cached, _ := memCache.Get(ctx, "tokens:access")
	if cached != 100 {
		t.Errorf("Expected cached value 100, got %d", cached)
	}
}

//nolint:dupl // Similar test structure to GetPendingDeviceCodesCount test is intentional
func TestMetricsCacheWrapper_GetTotalDeviceCodesCount_WithCacheAside(t *testing.T) {
	ctx := context.Background()
	mockCache := &mockCacheAside{
		MemoryCache: cache.NewMemoryCache(),
	}

	callCount := 0
	store := &mockStore{
		countTotalDeviceCodesFunc: func() (int64, error) {
			callCount++
			return 100, nil
		},
	}

	wrapper := newTestCacheWrapper(store, mockCache)

	// First call - cache miss, should query DB
	count, err := wrapper.GetTotalDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 100 {
		t.Errorf("Expected count 100, got %d", count)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 DB call, got %d", callCount)
	}

	if !mockCache.getWithFetchCalled {
		t.Error("Expected GetWithFetch to be called")
	}

	// Second call - should hit cache (no DB call)
	count2, err2 := wrapper.GetTotalDeviceCodesCount(ctx, time.Minute)
	if err2 != nil {
		t.Fatalf("Expected no error on second call, got %v", err2)
	}

	if count2 != 100 {
		t.Errorf("Expected cached value 100, got %d", count2)
	}

	if callCount != 1 {
		t.Errorf("Expected still 1 DB call (cache hit), got %d", callCount)
	}
}

//nolint:dupl // Similar test structure to GetTotalDeviceCodesCount test is intentional
func TestMetricsCacheWrapper_GetPendingDeviceCodesCount_WithCacheAside(t *testing.T) {
	ctx := context.Background()
	mockCache := &mockCacheAside{
		MemoryCache: cache.NewMemoryCache(),
	}

	callCount := 0
	store := &mockStore{
		countPendingDeviceCodesFunc: func() (int64, error) {
			callCount++
			return 25, nil
		},
	}

	wrapper := newTestCacheWrapper(store, mockCache)

	// First call - cache miss, should query DB
	count, err := wrapper.GetPendingDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 25 {
		t.Errorf("Expected count 25, got %d", count)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 DB call, got %d", callCount)
	}

	if !mockCache.getWithFetchCalled {
		t.Error("Expected GetWithFetch to be called")
	}

	// Second call - should hit cache (no DB call)
	count2, err2 := wrapper.GetPendingDeviceCodesCount(ctx, time.Minute)
	if err2 != nil {
		t.Fatalf("Expected no error on second call, got %v", err2)
	}

	if count2 != 25 {
		t.Errorf("Expected cached value 25, got %d", count2)
	}

	if callCount != 1 {
		t.Errorf("Expected still 1 DB call (cache hit), got %d", callCount)
	}
}
