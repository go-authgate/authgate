package cache

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// CacheMetrics holds Prometheus counters for cache operations.
type CacheMetrics struct {
	hits   *prometheus.CounterVec
	misses *prometheus.CounterVec
	errors *prometheus.CounterVec
}

var (
	cacheMetrics     *CacheMetrics
	cacheMetricsOnce sync.Once
)

// getCacheMetrics returns the singleton CacheMetrics instance.
// Uses sync.Once to ensure Prometheus metrics are only registered once.
func getCacheMetrics() *CacheMetrics {
	cacheMetricsOnce.Do(func() {
		cacheMetrics = &CacheMetrics{
			hits: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "cache_hits_total",
					Help: "Total number of cache hits",
				},
				[]string{"cache_name"},
			),
			misses: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "cache_misses_total",
					Help: "Total number of cache misses",
				},
				[]string{"cache_name"},
			),
			errors: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "cache_errors_total",
					Help: "Total number of cache errors (excluding cache misses)",
				},
				[]string{"cache_name", "operation"},
			),
		}
	})
	return cacheMetrics
}
