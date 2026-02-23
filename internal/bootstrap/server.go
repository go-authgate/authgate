package bootstrap

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/metrics"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/appleboy/graceful"
	"github.com/redis/go-redis/v9"
)

// createHTTPServer creates the HTTP server instance
func createHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.ServerAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// addServerRunningJob adds the HTTP server running job
func addServerRunningJob(m *graceful.Manager, srv *http.Server) {
	m.AddRunningJob(func(ctx context.Context) error {
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		}()
		<-ctx.Done()
		return nil
	})
}

// addServerShutdownJob adds HTTP server shutdown handler
func addServerShutdownJob(m *graceful.Manager, srv *http.Server) {
	m.AddShutdownJob(func() error {
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
			return err
		}

		log.Println("Server exited")
		return nil
	})
}

// addRedisClientShutdownJob adds Redis client shutdown handler
func addRedisClientShutdownJob(m *graceful.Manager, redisClient *redis.Client) {
	if redisClient == nil {
		return
	}

	m.AddShutdownJob(func() error {
		log.Println("Closing Redis connection...")
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis client: %v", err)
			return err
		}
		log.Println("Redis connection closed")
		return nil
	})
}

// addAuditServiceShutdownJob adds audit service shutdown handler
func addAuditServiceShutdownJob(m *graceful.Manager, auditService *services.AuditService) {
	m.AddShutdownJob(func() error {
		log.Println("Shutting down audit service...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := auditService.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down audit service: %v", err)
			return err
		}
		return nil
	})
}

// addAuditLogCleanupJob adds periodic audit log cleanup job
func addAuditLogCleanupJob(
	m *graceful.Manager,
	cfg *config.Config,
	auditService *services.AuditService,
) {
	if !cfg.EnableAuditLogging || cfg.AuditLogRetention <= 0 {
		return
	}

	m.AddRunningJob(func(ctx context.Context) error {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Run cleanup immediately on startup
		if deleted, err := auditService.CleanupOldLogs(cfg.AuditLogRetention); err != nil {
			log.Printf("Failed to cleanup old audit logs: %v", err)
		} else if deleted > 0 {
			log.Printf("Cleaned up %d old audit logs", deleted)
		}

		for {
			select {
			case <-ticker.C:
				if deleted, err := auditService.CleanupOldLogs(
					cfg.AuditLogRetention,
				); err != nil {
					log.Printf("Failed to cleanup old audit logs: %v", err)
				} else if deleted > 0 {
					log.Printf("Cleaned up %d old audit logs", deleted)
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
}

// addMetricsGaugeUpdateJob adds periodic metrics gauge update job
func addMetricsGaugeUpdateJob(
	m *graceful.Manager,
	cfg *config.Config,
	db *store.Store,
	prometheusMetrics metrics.MetricsRecorder,
	metricsCache cache.Cache,
) {
	if !cfg.MetricsEnabled || !cfg.MetricsGaugeUpdateEnabled {
		return
	}

	m.AddRunningJob(func(ctx context.Context) error {
		ticker := time.NewTicker(cfg.MetricsGaugeUpdateInterval)
		defer ticker.Stop()

		// Create cache wrapper
		cacheWrapper := metrics.NewMetricsCacheWrapper(db, metricsCache)

		// Update immediately on startup
		updateGaugeMetricsWithCache(
			ctx,
			cacheWrapper,
			prometheusMetrics,
			cfg.MetricsGaugeUpdateInterval,
		)

		for {
			select {
			case <-ticker.C:
				updateGaugeMetricsWithCache(
					ctx,
					cacheWrapper,
					prometheusMetrics,
					cfg.MetricsGaugeUpdateInterval,
				)
			case <-ctx.Done():
				return nil
			}
		}
	})
}

// addCacheCleanupJob adds cache cleanup on shutdown
func addCacheCleanupJob(m *graceful.Manager, metricsCacheCloser func() error) {
	if metricsCacheCloser == nil {
		return
	}

	m.AddShutdownJob(func() error {
		if err := metricsCacheCloser(); err != nil {
			log.Printf("Error closing metrics cache: %v", err)
		} else {
			log.Println("Metrics cache closed")
		}
		return nil
	})
}

// errorLogger handles rate-limited error logging
type errorLogger struct {
	lastErrorTimes  map[string]time.Time
	rateLimitWindow time.Duration
}

// newErrorLogger creates a new error logger with rate limiting
func newErrorLogger() *errorLogger {
	return &errorLogger{
		lastErrorTimes:  make(map[string]time.Time),
		rateLimitWindow: 5 * time.Minute, // Log at most once per 5 minutes per operation
	}
}

// logIfNeeded logs an error only if rate limit allows
func (e *errorLogger) logIfNeeded(operation string, err error) {
	now := time.Now()
	lastTime, exists := e.lastErrorTimes[operation]

	if !exists || now.Sub(lastTime) >= e.rateLimitWindow {
		log.Printf("Database query failed for %s: %v (further errors will be suppressed for %v)",
			operation, err, e.rateLimitWindow)
		e.lastErrorTimes[operation] = now
	}
}

var gaugeErrorLogger = newErrorLogger()

// updateGaugeMetricsWithCache updates gauge metrics using a cache-backed store.
// This reduces database load in multi-instance deployments by caching query results.
// The cache TTL should match the update interval to ensure consistent behavior.
func updateGaugeMetricsWithCache(
	ctx context.Context,
	cacheWrapper *metrics.MetricsCacheWrapper,
	m metrics.MetricsRecorder,
	cacheTTL time.Duration,
) {
	// Update active access tokens count
	activeAccessTokens, err := cacheWrapper.GetActiveTokensCount(ctx, "access", cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_access_tokens")
		gaugeErrorLogger.logIfNeeded("count_access_tokens", err)
	} else {
		m.SetActiveTokensCount("access", int(activeAccessTokens))
	}

	// Update active refresh tokens count
	activeRefreshTokens, err := cacheWrapper.GetActiveTokensCount(ctx, "refresh", cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_refresh_tokens")
		gaugeErrorLogger.logIfNeeded("count_refresh_tokens", err)
	} else {
		m.SetActiveTokensCount("refresh", int(activeRefreshTokens))
	}

	// Update active device codes count
	totalDeviceCodes, err := cacheWrapper.GetTotalDeviceCodesCount(ctx, cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_total_device_codes")
		gaugeErrorLogger.logIfNeeded("count_total_device_codes", err)
		totalDeviceCodes = 0
	}

	pendingDeviceCodes, err := cacheWrapper.GetPendingDeviceCodesCount(ctx, cacheTTL)
	if err != nil {
		m.RecordDatabaseQueryError("count_pending_device_codes")
		gaugeErrorLogger.logIfNeeded("count_pending_device_codes", err)
		pendingDeviceCodes = 0
	}

	m.SetActiveDeviceCodesCount(int(totalDeviceCodes), int(pendingDeviceCodes))
}
