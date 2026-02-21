package bootstrap

import (
	"log"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/middleware"
	"github.com/appleboy/authgate/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// rateLimitMiddlewares holds rate limiting middlewares for different endpoints
type rateLimitMiddlewares struct {
	login        gin.HandlerFunc
	deviceCode   gin.HandlerFunc
	token        gin.HandlerFunc
	deviceVerify gin.HandlerFunc
}

// setupRateLimiting configures rate limiting middlewares based on configuration
// Accepts an optional go-redis client
func setupRateLimiting(
	cfg *config.Config,
	auditService *services.AuditService,
	redisClient *redis.Client,
) rateLimitMiddlewares {
	// Return no-op middlewares when rate limiting is disabled
	noOpMiddleware := func(c *gin.Context) { c.Next() }
	disabledLimiters := rateLimitMiddlewares{
		login:        noOpMiddleware,
		deviceCode:   noOpMiddleware,
		token:        noOpMiddleware,
		deviceVerify: noOpMiddleware,
	}

	switch {
	case !cfg.EnableRateLimit:
		return disabledLimiters
	default:
		return createRateLimiters(cfg, auditService, redisClient)
	}
}

// createRateLimiters creates rate limiting middlewares for all endpoints
// Accepts an optional go-redis client
func createRateLimiters(
	cfg *config.Config,
	auditService *services.AuditService,
	redisClient *redis.Client,
) rateLimitMiddlewares {
	log.Printf("Rate limiting enabled (store: %s)", cfg.RateLimitStore)

	storeType := middleware.RateLimitStoreType(cfg.RateLimitStore)

	// Log rate limiting configuration
	if storeType == middleware.RateLimitStoreRedis {
		log.Printf("Using shared Redis client for rate limiting (provided externally)")
	} else {
		log.Printf("In-memory rate limiting configured (single instance only)")
	}

	createLimiter := func(requestsPerMinute int, endpoint string) gin.HandlerFunc {
		limiter, err := middleware.NewRateLimiter(middleware.RateLimitConfig{
			RequestsPerMinute: requestsPerMinute,
			StoreType:         storeType,
			RedisClient:       redisClient, // Use provided client (nil for memory store)
			CleanupInterval:   cfg.RateLimitCleanupInterval,
			AuditService:      auditService, // Add audit service for logging
		})
		if err != nil {
			log.Fatalf("Failed to create rate limiter for %s: %v", endpoint, err)
		}
		return limiter
	}

	return rateLimitMiddlewares{
		login:        createLimiter(cfg.LoginRateLimit, "/login"),
		deviceCode:   createLimiter(cfg.DeviceCodeRateLimit, "/oauth/device/code"),
		token:        createLimiter(cfg.TokenRateLimit, "/oauth/token"),
		deviceVerify: createLimiter(cfg.DeviceVerifyRateLimit, "/device/verify"),
	}
}
