package cache

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/go-authgate/authgate/internal/core"

	"github.com/prometheus/client_golang/prometheus"
)

// Compile-time interface check.
var _ core.Cache[struct{}] = (*InstrumentedCache[struct{}])(nil)

// InstrumentedCache wraps a Cache with Prometheus hit/miss/error counters.
type InstrumentedCache[T any] struct {
	underlying core.Cache[T]

	// Pre-resolved counters (avoids WithLabelValues map lookup per call).
	hitCounter  prometheus.Counter
	missCounter prometheus.Counter
	errGet      prometheus.Counter
	errSet      prometheus.Counter
	errDelete   prometheus.Counter
	errHealth   prometheus.Counter
	errFetch    prometheus.Counter
}

// NewInstrumentedCache creates a new instrumented cache wrapper.
// cacheName is used as a Prometheus label to distinguish between different caches.
func NewInstrumentedCache[T any](underlying core.Cache[T], cacheName string) *InstrumentedCache[T] {
	m := getMetrics()
	return &InstrumentedCache[T]{
		underlying:  underlying,
		hitCounter:  m.hits.WithLabelValues(cacheName),
		missCounter: m.misses.WithLabelValues(cacheName),
		errGet:      m.errors.WithLabelValues(cacheName, opGet),
		errSet:      m.errors.WithLabelValues(cacheName, opSet),
		errDelete:   m.errors.WithLabelValues(cacheName, opDelete),
		errHealth:   m.errors.WithLabelValues(cacheName, opHealth),
		errFetch:    m.errors.WithLabelValues(cacheName, opGetWithFetch),
	}
}

func (i *InstrumentedCache[T]) Get(ctx context.Context, key string) (T, error) {
	value, err := i.underlying.Get(ctx, key)
	switch {
	case err == nil:
		i.hitCounter.Inc()
	case errors.Is(err, ErrCacheMiss):
		i.missCounter.Inc()
	default:
		i.errGet.Inc()
	}
	return value, err
}

func (i *InstrumentedCache[T]) Set(
	ctx context.Context,
	key string,
	value T,
	ttl time.Duration,
) error {
	err := i.underlying.Set(ctx, key, value, ttl)
	if err != nil {
		i.errSet.Inc()
	}
	return err
}

func (i *InstrumentedCache[T]) Delete(ctx context.Context, key string) error {
	err := i.underlying.Delete(ctx, key)
	if err != nil {
		i.errDelete.Inc()
	}
	return err
}

func (i *InstrumentedCache[T]) Close() error {
	return i.underlying.Close()
}

func (i *InstrumentedCache[T]) Health(ctx context.Context) error {
	err := i.underlying.Health(ctx)
	if err != nil {
		i.errHealth.Inc()
	}
	return err
}

// GetWithFetch implements the cache-aside pattern with metrics instrumentation.
// Wraps fetchFunc to detect whether it was called (miss) or not (hit), without
// calling underlying.Get() a second time. This preserves optimizations in the
// underlying implementation (e.g., stampede protection in RueidisAsideCache).
// Uses atomic.Bool because singleflight may set fetchCalled from a shared
// goroutine while the caller returns early on context cancellation.
func (i *InstrumentedCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	var fetchCalled atomic.Bool
	wrapped := func(ctx context.Context, key string) (T, error) {
		fetchCalled.Store(true)
		return fetchFunc(ctx, key)
	}

	value, err := i.underlying.GetWithFetch(ctx, key, ttl, wrapped)
	if fetchCalled.Load() {
		i.missCounter.Inc()
	} else if err == nil {
		i.hitCounter.Inc()
	}
	if err != nil && !errors.Is(err, ErrCacheMiss) {
		i.errFetch.Inc()
	}
	return value, err
}
