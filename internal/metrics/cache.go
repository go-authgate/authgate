package metrics

import (
	"context"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/store"
)

// metricsStore defines the interface for database operations needed by CacheWrapper.
// This interface allows for easier testing without requiring a full store.Store.
type metricsStore interface {
	CountActiveTokensByCategory(category string) (int64, error)
	CountTotalDeviceCodes() (int64, error)
	CountPendingDeviceCodes() (int64, error)
}

// CacheWrapper provides a read-through cache for metrics data.
// It queries the database on cache miss and updates the cache for subsequent requests.
// Uses the cache's GetWithFetch method for optimal cache-aside pattern support.
type CacheWrapper struct {
	store metricsStore
	cache cache.Cache[int64]
}

// NewCacheWrapper creates a new cache wrapper for metrics.
func NewCacheWrapper(store *store.Store, cache cache.Cache[int64]) *CacheWrapper {
	return &CacheWrapper{
		store: store,
		cache: cache,
	}
}

// GetActiveTokensCount retrieves the count of active tokens by category.
// Uses cache-aside pattern via GetWithFetch for optimal performance.
func (m *CacheWrapper) GetActiveTokensCount(
	ctx context.Context,
	category string,
	ttl time.Duration,
) (int64, error) {
	return m.getCountWithCache(
		ctx,
		"tokens:"+category,
		ttl,
		func() (int64, error) {
			return m.store.CountActiveTokensByCategory(category)
		},
	)
}

// getCountWithCache retrieves a count using the cache-aside pattern.
func (m *CacheWrapper) getCountWithCache(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func() (int64, error),
) (int64, error) {
	return m.cache.GetWithFetch(
		ctx,
		key,
		ttl,
		func(ctx context.Context, key string) (int64, error) {
			return fetchFunc()
		},
	)
}

// GetTotalDeviceCodesCount retrieves the count of total (non-expired) device codes.
// Uses cache-aside pattern via GetWithFetch for optimal performance.
func (m *CacheWrapper) GetTotalDeviceCodesCount(
	ctx context.Context,
	ttl time.Duration,
) (int64, error) {
	return m.getCountWithCache(
		ctx,
		"devices:total",
		ttl,
		m.store.CountTotalDeviceCodes,
	)
}

// GetPendingDeviceCodesCount retrieves the count of pending (not yet authorized) device codes.
// Uses cache-aside pattern via GetWithFetch for optimal performance.
func (m *CacheWrapper) GetPendingDeviceCodesCount(
	ctx context.Context,
	ttl time.Duration,
) (int64, error) {
	return m.getCountWithCache(
		ctx,
		"devices:pending",
		ttl,
		m.store.CountPendingDeviceCodes,
	)
}
