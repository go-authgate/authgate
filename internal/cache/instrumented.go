package cache

import (
	"context"
	"errors"
	"time"

	"github.com/go-authgate/authgate/internal/core"
)

// Compile-time interface check.
var _ core.Cache[struct{}] = (*InstrumentedCache[struct{}])(nil)

// InstrumentedCache wraps a cache implementation with Prometheus metrics instrumentation.
// Records cache hits, misses, and errors for observability.
// This wrapper is transparent and does not change cache behavior.
type InstrumentedCache[T any] struct {
	underlying core.Cache[T]
	cacheName  string
	metrics    *CacheMetrics
}

// NewInstrumentedCache creates a new instrumented cache wrapper.
// cacheName is used as a Prometheus label to distinguish between different caches.
func NewInstrumentedCache[T any](underlying core.Cache[T], cacheName string) *InstrumentedCache[T] {
	return &InstrumentedCache[T]{
		underlying: underlying,
		cacheName:  cacheName,
		metrics:    getCacheMetrics(),
	}
}

// Get retrieves a value from cache and records metrics.
// Success (err == nil) → cache hit
// ErrCacheMiss → cache miss
// Other errors → cache error
func (i *InstrumentedCache[T]) Get(ctx context.Context, key string) (T, error) {
	value, err := i.underlying.Get(ctx, key)

	if err == nil {
		i.metrics.hits.WithLabelValues(i.cacheName).Inc()
		return value, nil
	}

	if errors.Is(err, ErrCacheMiss) {
		i.metrics.misses.WithLabelValues(i.cacheName).Inc()
		return value, err
	}

	// Other errors (Redis down, connection failed, etc.)
	i.metrics.errors.WithLabelValues(i.cacheName, "get").Inc()
	return value, err
}

// Set stores a value in cache and records errors.
func (i *InstrumentedCache[T]) Set(
	ctx context.Context,
	key string,
	value T,
	ttl time.Duration,
) error {
	err := i.underlying.Set(ctx, key, value, ttl)
	if err != nil {
		i.metrics.errors.WithLabelValues(i.cacheName, "set").Inc()
	}
	return err
}

// Delete removes a key from cache and records errors.
func (i *InstrumentedCache[T]) Delete(ctx context.Context, key string) error {
	err := i.underlying.Delete(ctx, key)
	if err != nil {
		i.metrics.errors.WithLabelValues(i.cacheName, "delete").Inc()
	}
	return err
}

// Close closes the underlying cache connection.
func (i *InstrumentedCache[T]) Close() error {
	return i.underlying.Close()
}

// Health checks the underlying cache health and records errors.
func (i *InstrumentedCache[T]) Health(ctx context.Context) error {
	err := i.underlying.Health(ctx)
	if err != nil {
		i.metrics.errors.WithLabelValues(i.cacheName, "health").Inc()
	}
	return err
}

// GetWithFetch implements the cache-aside pattern with metrics instrumentation.
// Attempts to get from cache first:
// - Cache hit → record hit, return immediately
// - Cache miss (ErrCacheMiss) → record miss, delegate to underlying.GetWithFetch
// - Cache error → record error, delegate to underlying.GetWithFetch (resilience)
//
// We delegate to underlying.GetWithFetch rather than calling fetchFunc directly
// because some implementations (e.g., RueidisAsideCache) have optimized GetWithFetch
// with stampede protection and client-side caching.
func (i *InstrumentedCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	// Try cache first
	value, err := i.underlying.Get(ctx, key)
	if err == nil {
		// Cache hit
		i.metrics.hits.WithLabelValues(i.cacheName).Inc()
		return value, nil
	}

	// Cache miss or error
	if errors.Is(err, ErrCacheMiss) {
		i.metrics.misses.WithLabelValues(i.cacheName).Inc()
	} else {
		// Other error (Redis down, etc.) - record but continue with fetch for resilience
		i.metrics.errors.WithLabelValues(i.cacheName, "get_with_fetch").Inc()
	}

	// Delegate to underlying implementation's GetWithFetch
	// (may have optimizations like stampede protection)
	return i.underlying.GetWithFetch(ctx, key, ttl, fetchFunc)
}
