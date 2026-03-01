package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/mocks"
)

// callFetchFn is a DoAndReturn helper that invokes the cache fetch function,
// simulating a cache miss where the real DB fetch is executed.
func callFetchFn[T any](
	_ context.Context,
	key string,
	_ time.Duration,
	fn func(context.Context, string) (T, error),
) (T, error) {
	return fn(context.Background(), key)
}

func TestCacheWrapper_GetActiveTokensCount_CacheHit(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)
	// No expectations: if CountActiveTokensByCategory is called, gomock fails automatically

	wrapper := NewCacheWrapper(mockStore, memCache)

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

func TestCacheWrapper_GetActiveTokensCount_CacheMiss(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)
	mockStore.EXPECT().CountActiveTokensByCategory("access").Return(int64(100), nil).Times(1)

	wrapper := NewCacheWrapper(mockStore, memCache)

	count, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 100 {
		t.Errorf("Expected count 100, got %d", count)
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

func TestCacheWrapper_GetActiveTokensCount_DBError(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	expectedErr := errors.New("database connection failed")
	mockStore := mocks.NewMockMetricsStore(ctrl)
	mockStore.EXPECT().CountActiveTokensByCategory("access").Return(int64(0), expectedErr).Times(1)

	wrapper := NewCacheWrapper(mockStore, memCache)

	_, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestCacheWrapper_GetActiveTokensCount_CacheExpiration(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)

	callCount := 0
	gomock.InOrder(
		mockStore.EXPECT().
			CountActiveTokensByCategory("access").
			DoAndReturn(func(category string) (int64, error) {
				callCount++
				return int64(callCount * 10), nil
			}),
		mockStore.EXPECT().
			CountActiveTokensByCategory("access").
			DoAndReturn(func(category string) (int64, error) {
				callCount++
				return int64(callCount * 10), nil
			}),
	)

	wrapper := NewCacheWrapper(mockStore, memCache)

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

func TestCacheWrapper_GetTotalDeviceCodesCount_CacheHit(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)
	// No expectations: if CountTotalDeviceCodes is called, gomock fails automatically

	wrapper := NewCacheWrapper(mockStore, memCache)

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

func TestCacheWrapper_GetPendingDeviceCodesCount_CacheHit(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)
	// No expectations: if CountPendingDeviceCodes is called, gomock fails automatically

	wrapper := NewCacheWrapper(mockStore, memCache)

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

func TestCacheWrapper_GetTotalDeviceCodesCount_CacheMiss(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)
	mockStore.EXPECT().CountTotalDeviceCodes().Return(int64(200), nil).Times(1)

	wrapper := NewCacheWrapper(mockStore, memCache)

	count, err := wrapper.GetTotalDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 200 {
		t.Errorf("Expected count 200, got %d", count)
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

func TestCacheWrapper_GetPendingDeviceCodesCount_CacheMiss(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)
	mockStore.EXPECT().CountPendingDeviceCodes().Return(int64(50), nil).Times(1)

	wrapper := NewCacheWrapper(mockStore, memCache)

	count, err := wrapper.GetPendingDeviceCodesCount(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 50 {
		t.Errorf("Expected count 50, got %d", count)
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

func TestCacheWrapper_GetTotalDeviceCodesCount_DBError(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	expectedErr := errors.New("database timeout")
	mockStore := mocks.NewMockMetricsStore(ctrl)
	mockStore.EXPECT().CountTotalDeviceCodes().Return(int64(0), expectedErr).Times(1)

	wrapper := NewCacheWrapper(mockStore, memCache)

	_, err := wrapper.GetTotalDeviceCodesCount(ctx, time.Minute)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestCacheWrapper_GetPendingDeviceCodesCount_DBError(t *testing.T) {
	ctx := context.Background()
	memCache := cache.NewMemoryCache[int64]()
	ctrl := gomock.NewController(t)
	expectedErr := errors.New("database timeout")
	mockStore := mocks.NewMockMetricsStore(ctrl)
	mockStore.EXPECT().CountPendingDeviceCodes().Return(int64(0), expectedErr).Times(1)

	wrapper := NewCacheWrapper(mockStore, memCache)

	_, err := wrapper.GetPendingDeviceCodesCount(ctx, time.Minute)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestCacheWrapper_UsesGetWithFetch(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)
	mockStore.EXPECT().CountActiveTokensByCategory("access").Return(int64(42), nil).Times(1)

	mockCache := mocks.NewMockCache[int64](ctrl)
	mockCache.EXPECT().
		GetWithFetch(gomock.Any(), "tokens:access", time.Minute, gomock.Any()).
		DoAndReturn(callFetchFn[int64]).
		Times(1)

	wrapper := NewCacheWrapper(mockStore, mockCache)

	count, err := wrapper.GetActiveTokensCount(ctx, "access", time.Minute)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count != 42 {
		t.Errorf("Expected count 42, got %d", count)
	}
}

//nolint:dupl // Similar test structure to GetPendingDeviceCodesCount test is intentional
func TestCacheWrapper_GetTotalDeviceCodesCount_WithCacheAside(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)

	callCount := 0
	mockStore.EXPECT().CountTotalDeviceCodes().DoAndReturn(func() (int64, error) {
		callCount++
		return int64(100), nil
	}).Times(1)

	mockCache := mocks.NewMockCache[int64](ctrl)
	gomock.InOrder(
		mockCache.EXPECT().GetWithFetch(gomock.Any(), "devices:total", gomock.Any(), gomock.Any()).
			DoAndReturn(callFetchFn[int64]),
		mockCache.EXPECT().GetWithFetch(gomock.Any(), "devices:total", gomock.Any(), gomock.Any()).
			Return(int64(100), nil),
	)

	wrapper := NewCacheWrapper(mockStore, mockCache)

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
func TestCacheWrapper_GetPendingDeviceCodesCount_WithCacheAside(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	mockStore := mocks.NewMockMetricsStore(ctrl)

	callCount := 0
	mockStore.EXPECT().CountPendingDeviceCodes().DoAndReturn(func() (int64, error) {
		callCount++
		return int64(25), nil
	}).Times(1)

	mockCache := mocks.NewMockCache[int64](ctrl)
	gomock.InOrder(
		mockCache.EXPECT().
			GetWithFetch(gomock.Any(), "devices:pending", gomock.Any(), gomock.Any()).
			DoAndReturn(callFetchFn[int64]),
		mockCache.EXPECT().
			GetWithFetch(gomock.Any(), "devices:pending", gomock.Any(), gomock.Any()).
			Return(int64(25), nil),
	)

	wrapper := NewCacheWrapper(mockStore, mockCache)

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
