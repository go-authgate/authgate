package bootstrap

import (
	"context"
	"fmt"
	"log"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
)

// initializeMetrics initializes Prometheus metrics
func initializeMetrics(cfg *config.Config) metrics.Recorder {
	prometheusMetrics := metrics.Init(cfg.MetricsEnabled)
	if cfg.MetricsEnabled {
		log.Println("Prometheus metrics initialized")
	} else {
		log.Println("Metrics disabled (using noop implementation)")
	}
	return prometheusMetrics
}

// initializeMetricsCache initializes the metrics cache based on configuration
func initializeMetricsCache(
	ctx context.Context,
	cfg *config.Config,
) (cache.Cache[int64], func() error, error) {
	if !cfg.MetricsEnabled || !cfg.MetricsGaugeUpdateEnabled {
		return nil, nil, nil
	}

	// Create timeout context for cache initialization
	ctx, cancel := context.WithTimeout(ctx, cfg.CacheInitTimeout)
	defer cancel()

	var metricsCache cache.Cache[int64]
	var err error

	switch cfg.MetricsCacheType {
	case config.MetricsCacheTypeRedisAside:
		metricsCache, err = cache.NewRueidisAsideCache[int64](
			ctx,
			cfg.RedisAddr,
			cfg.RedisPassword,
			cfg.RedisDB,
			"authgate:metrics:",
			cfg.MetricsCacheClientTTL,
			cfg.MetricsCacheSizePerConn,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize redis-aside metrics cache: %w", err)
		}
		log.Printf(
			"Metrics cache: redis-aside (addr=%s, db=%d, client_ttl=%s, cache_size_per_conn=%dMB)",
			cfg.RedisAddr,
			cfg.RedisDB,
			cfg.MetricsCacheClientTTL,
			cfg.MetricsCacheSizePerConn,
		)

	case config.MetricsCacheTypeRedis:
		metricsCache, err = cache.NewRueidisCache[int64](
			ctx,
			cfg.RedisAddr,
			cfg.RedisPassword,
			cfg.RedisDB,
			"authgate:metrics:",
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize redis metrics cache: %w", err)
		}
		log.Printf("Metrics cache: redis (addr=%s, db=%d)", cfg.RedisAddr, cfg.RedisDB)

	default: // memory
		metricsCache = cache.NewMemoryCache[int64]()
		log.Println("Metrics cache: memory (single instance only)")
	}

	return metricsCache, metricsCache.Close, nil
}

// initializeUserCache initializes the user cache (always enabled, defaults to memory)
func initializeUserCache(
	ctx context.Context,
	cfg *config.Config,
) (cache.Cache[models.User], func() error, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.CacheInitTimeout)
	defer cancel()

	switch cfg.UserCacheType {
	case config.UserCacheTypeRedisAside:
		c, err := cache.NewRueidisAsideCache[models.User](
			ctx,
			cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB,
			"authgate:users:",
			cfg.UserCacheClientTTL,
			cfg.UserCacheSizePerConn,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize redis-aside user cache: %w", err)
		}
		log.Printf(
			"User cache: redis-aside (addr=%s, db=%d, client_ttl=%s, cache_size_per_conn=%dMB)",
			cfg.RedisAddr,
			cfg.RedisDB,
			cfg.UserCacheClientTTL,
			cfg.UserCacheSizePerConn,
		)
		return c, c.Close, nil

	case config.UserCacheTypeRedis:
		c, err := cache.NewRueidisCache[models.User](
			ctx,
			cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB,
			"authgate:users:",
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize redis user cache: %w", err)
		}
		log.Printf("User cache: redis (addr=%s, db=%d)", cfg.RedisAddr, cfg.RedisDB)
		return c, c.Close, nil

	default: // memory
		c := cache.NewMemoryCache[models.User]()
		log.Println("User cache: memory (single instance only)")
		return c, c.Close, nil
	}
}
