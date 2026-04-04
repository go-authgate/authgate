package cache

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Operation label values for cache_errors_total.
const (
	opGet          = "get"
	opSet          = "set"
	opDelete       = "delete"
	opHealth       = "health"
	opGetWithFetch = "get_with_fetch"
)

// Metrics holds Prometheus counters for cache operations.
type Metrics struct {
	hits   *prometheus.CounterVec
	misses *prometheus.CounterVec
	errors *prometheus.CounterVec
}

var (
	cacheMetrics     *Metrics
	cacheMetricsOnce sync.Once
)

// getMetrics returns the singleton Metrics instance.
// Uses sync.Once to ensure Prometheus metrics are only registered once.
func getMetrics() *Metrics {
	cacheMetricsOnce.Do(func() {
		cacheMetrics = &Metrics{
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
