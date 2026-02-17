package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/appleboy/authgate/internal/cache"
	"github.com/appleboy/authgate/internal/store"
)

// metricsStore defines the interface for database operations needed by MetricsCacheWrapper.
// This interface allows for easier testing without requiring a full store.Store.
type metricsStore interface {
	CountActiveTokensByCategory(category string) (int64, error)
	CountTotalDeviceCodes() (int64, error)
	CountPendingDeviceCodes() (int64, error)
}

// cacheAsideSupport is an optional interface that cache implementations can provide
// to enable more efficient cache-aside pattern (used by rueidisaside).
type cacheAsideSupport interface {
	GetWithFetch(
		ctx context.Context,
		key string,
		ttl time.Duration,
		fetchFunc func(ctx context.Context, key string) (int64, error),
	) (int64, error)
}

// MetricsCacheWrapper provides a read-through cache for metrics data.
// It queries the database on cache miss and updates the cache for subsequent requests.
type MetricsCacheWrapper struct {
	store metricsStore
	cache cache.Cache
}

// NewMetricsCacheWrapper creates a new cache wrapper for metrics.
func NewMetricsCacheWrapper(store *store.Store, cache cache.Cache) *MetricsCacheWrapper {
	return &MetricsCacheWrapper{
		store: store,
		cache: cache,
	}
}

// GetActiveTokensCount retrieves the count of active tokens by category.
// It uses cache-aside pattern, automatically leveraging rueidisaside if available.
func (m *MetricsCacheWrapper) GetActiveTokensCount(
	ctx context.Context,
	category string,
	ttl time.Duration,
) (int64, error) {
	return m.getCountWithCache(
		ctx,
		fmt.Sprintf("tokens:%s", category),
		ttl,
		func() (int64, error) {
			return m.store.CountActiveTokensByCategory(category)
		},
	)
}

// getCountWithCache is a generic helper for cache-aside pattern.
// It automatically uses GetWithFetch if available (rueidisaside), otherwise falls back to manual cache-aside.
func (m *MetricsCacheWrapper) getCountWithCache(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func() (int64, error),
) (int64, error) {
	// If cache supports GetWithFetch (e.g., rueidisaside), use it for optimal cache-aside
	if asideCache, ok := m.cache.(cacheAsideSupport); ok {
		return asideCache.GetWithFetch(
			ctx,
			key,
			ttl,
			func(ctx context.Context, key string) (int64, error) {
				return fetchFunc()
			},
		)
	}

	// Fallback to manual cache-aside pattern for simple caches (memory, basic redis)
	// Try cache first
	if count, err := m.cache.Get(ctx, key); err == nil {
		return count, nil
	} else if err != cache.ErrCacheMiss {
		// Log cache errors but continue with DB query (graceful degradation)
		slog.Warn("Cache error, falling back to database",
			"error", err,
			"key", key,
		)
	}

	// Cache miss - query database
	count, err := fetchFunc()
	if err != nil {
		return 0, err
	}

	// Update cache (fire-and-forget)
	if setErr := m.cache.Set(ctx, key, count, ttl); setErr != nil {
		slog.Debug("Failed to update cache",
			"error", setErr,
			"key", key,
		)
	}

	return count, nil
}

// GetTotalDeviceCodesCount retrieves the count of total (non-expired) device codes.
// Uses cache-aside pattern, automatically leveraging rueidisaside if available.
func (m *MetricsCacheWrapper) GetTotalDeviceCodesCount(
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
// Uses cache-aside pattern, automatically leveraging rueidisaside if available.
func (m *MetricsCacheWrapper) GetPendingDeviceCodesCount(
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
