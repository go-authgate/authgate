package bootstrap

import (
	"log"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
)

// initializeMetrics initializes Prometheus metrics
func initializeMetrics(cfg *config.Config) metrics.MetricsRecorder {
	prometheusMetrics := metrics.Init(cfg.MetricsEnabled)
	if cfg.MetricsEnabled {
		log.Println("Prometheus metrics initialized")
	} else {
		log.Println("Metrics disabled (using noop implementation)")
	}
	return prometheusMetrics
}

// initializeMetricsCache initializes the metrics cache based on configuration
func initializeMetricsCache(cfg *config.Config) (cache.Cache, func() error) {
	if !cfg.MetricsEnabled || !cfg.MetricsGaugeUpdateEnabled {
		return nil, nil
	}

	var metricsCache cache.Cache
	var err error

	switch cfg.MetricsCacheType {
	case config.MetricsCacheTypeRedisAside:
		metricsCache, err = cache.NewRueidisAsideCache(
			cfg.RedisAddr,
			cfg.RedisPassword,
			cfg.RedisDB,
			"metrics:",
			cfg.MetricsCacheClientTTL,
			cfg.MetricsCacheSizePerConn,
		)
		if err != nil {
			log.Fatalf("Failed to initialize redis-aside metrics cache: %v", err)
		}
		log.Printf(
			"Metrics cache: redis-aside (addr=%s, db=%d, client_ttl=%s, cache_size_per_conn=%dMB)",
			cfg.RedisAddr,
			cfg.RedisDB,
			cfg.MetricsCacheClientTTL,
			cfg.MetricsCacheSizePerConn,
		)
	case config.MetricsCacheTypeRedis:
		metricsCache, err = cache.NewRueidisCache(
			cfg.RedisAddr,
			cfg.RedisPassword,
			cfg.RedisDB,
			"metrics:",
		)
		if err != nil {
			log.Fatalf("Failed to initialize redis metrics cache: %v", err)
		}
		log.Printf("Metrics cache: redis (addr=%s, db=%d)", cfg.RedisAddr, cfg.RedisDB)
	default: // memory
		metricsCache = cache.NewMemoryCache()
		log.Println("Metrics cache: memory (single instance only)")
	}

	return metricsCache, metricsCache.Close
}
