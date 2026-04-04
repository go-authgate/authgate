package bootstrap

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/models"
)

// initializeMetrics initializes Prometheus metrics
func initializeMetrics(cfg *config.Config) core.Recorder {
	prometheusMetrics := metrics.Init(cfg.MetricsEnabled)
	if cfg.MetricsEnabled {
		log.Println("Prometheus metrics initialized")
	} else {
		log.Println("Metrics disabled (using noop implementation)")
	}
	return prometheusMetrics
}

// cacheOpts holds the parameters needed to initialise any typed cache.
type cacheOpts struct {
	cacheType   string
	cacheName   string // Prometheus label for metrics (e.g. "token", "client")
	keyPrefix   string
	clientTTL   time.Duration
	sizePerConn int
	label       string // human-readable name for log messages (e.g. "Metrics")
}

// initializeCache is a generic helper that creates a typed cache according to
// the supplied cacheOpts. All cache-init call-sites delegate to this.
func initializeCache[T any](
	ctx context.Context,
	cfg *config.Config,
	opts cacheOpts,
) (core.Cache[T], func() error, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.CacheInitTimeout)
	defer cancel()

	var underlyingCache core.Cache[T]
	var closeFunc func() error

	switch opts.cacheType {
	case config.CacheTypeRedisAside:
		c, err := cache.NewRueidisAsideCache[T](
			ctx,
			cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB,
			opts.keyPrefix, opts.clientTTL, opts.sizePerConn,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed to initialize redis-aside %s cache: %w",
				opts.label,
				err,
			)
		}
		log.Printf(
			"%s cache: redis-aside (addr=%s, db=%d, client_ttl=%s, cache_size_per_conn=%dMB)",
			opts.label, cfg.RedisAddr, cfg.RedisDB, opts.clientTTL, opts.sizePerConn,
		)
		underlyingCache = c
		closeFunc = c.Close

	case config.CacheTypeRedis:
		c, err := cache.NewRueidisCache[T](
			ctx,
			cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB,
			opts.keyPrefix,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize redis %s cache: %w", opts.label, err)
		}
		log.Printf("%s cache: redis (addr=%s, db=%d)", opts.label, cfg.RedisAddr, cfg.RedisDB)
		underlyingCache = c
		closeFunc = c.Close

	default: // memory
		c := cache.NewMemoryCache[T]()
		log.Printf("%s cache: memory (single instance only)", opts.label)
		underlyingCache = c
		closeFunc = c.Close
	}

	// Wrap with instrumentation if metrics are enabled
	if cfg.MetricsEnabled {
		instrumentedCache := cache.NewInstrumentedCache(underlyingCache, opts.cacheName)
		return instrumentedCache, closeFunc, nil
	}

	return underlyingCache, closeFunc, nil
}

// initializeMetricsCache initializes the metrics cache based on configuration
func initializeMetricsCache(
	ctx context.Context,
	cfg *config.Config,
) (core.Cache[int64], func() error, error) {
	if !cfg.MetricsEnabled || !cfg.MetricsGaugeUpdateEnabled {
		return nil, nil, nil
	}
	return initializeCache[int64](ctx, cfg, cacheOpts{
		cacheType:   cfg.MetricsCacheType,
		cacheName:   "metrics",
		keyPrefix:   "authgate:metrics:",
		clientTTL:   cfg.MetricsCacheClientTTL,
		sizePerConn: cfg.MetricsCacheSizePerConn,
		label:       "Metrics",
	})
}

// initializeClientCountCache initializes the pending-client count cache used by InjectPendingCount.
func initializeClientCountCache(
	ctx context.Context,
	cfg *config.Config,
) (core.Cache[int64], func() error, error) {
	return initializeCache[int64](ctx, cfg, cacheOpts{
		cacheType:   cfg.ClientCountCacheType,
		cacheName:   "client_count",
		keyPrefix:   "authgate:client-count:",
		clientTTL:   cfg.ClientCountCacheClientTTL,
		sizePerConn: cfg.ClientCountCacheSizePerConn,
		label:       "Client count",
	})
}

// initializeTokenCache initializes the token verification cache (disabled by default)
func initializeTokenCache(
	ctx context.Context,
	cfg *config.Config,
) (core.Cache[models.AccessToken], func() error, error) {
	if !cfg.TokenCacheEnabled {
		// Use NoopCache when token cache is disabled
		noop := cache.NewNoopCache[models.AccessToken]()
		// Still wrap with instrumentation if metrics enabled (shows 100% miss rate)
		if cfg.MetricsEnabled {
			instrumented := cache.NewInstrumentedCache(noop, "token")
			return instrumented, noop.Close, nil
		}
		return noop, noop.Close, nil
	}
	return initializeCache[models.AccessToken](ctx, cfg, cacheOpts{
		cacheType:   cfg.TokenCacheType,
		cacheName:   "token",
		keyPrefix:   "authgate:tokens:",
		clientTTL:   cfg.TokenCacheClientTTL,
		sizePerConn: cfg.TokenCacheSizePerConn,
		label:       "Token",
	})
}

// initializeClientCache initializes the OAuth client cache (always enabled, defaults to memory)
func initializeClientCache(
	ctx context.Context,
	cfg *config.Config,
) (core.Cache[models.OAuthApplication], func() error, error) {
	return initializeCache[models.OAuthApplication](ctx, cfg, cacheOpts{
		cacheType:   cfg.ClientCacheType,
		cacheName:   "client",
		keyPrefix:   "authgate:clients:",
		clientTTL:   cfg.ClientCacheClientTTL,
		sizePerConn: cfg.ClientCacheSizePerConn,
		label:       "Client",
	})
}

// initializeUserCache initializes the user cache (always enabled, defaults to memory)
func initializeUserCache(
	ctx context.Context,
	cfg *config.Config,
) (core.Cache[models.User], func() error, error) {
	return initializeCache[models.User](ctx, cfg, cacheOpts{
		cacheType:   cfg.UserCacheType,
		cacheName:   "user",
		keyPrefix:   "authgate:users:",
		clientTTL:   cfg.UserCacheClientTTL,
		sizePerConn: cfg.UserCacheSizePerConn,
		label:       "User",
	})
}
