package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	limiterRedis "github.com/ulule/limiter/v3/drivers/store/redis"
)

// RateLimitStoreType defines the type of rate limit store
type RateLimitStoreType string

const (
	// RateLimitStoreMemory uses in-memory storage (single instance only)
	RateLimitStoreMemory RateLimitStoreType = "memory"
	// RateLimitStoreRedis uses Redis storage (distributed, multi-pod support)
	RateLimitStoreRedis RateLimitStoreType = "redis"
)

// RateLimitConfig holds the configuration for rate limiting with store support
type RateLimitConfig struct {
	// Rate limit settings
	RequestsPerMinute int           // Number of requests allowed per minute
	CleanupInterval   time.Duration // How often to cleanup (only for memory store)

	// Store settings
	StoreType RateLimitStoreType // "memory" or "redis"

	// Redis settings (only used when StoreType = "redis")
	// Must be provided when StoreType is "redis" (initialized in main.go)
	RedisClient *redis.Client // Required for Redis store: shared go-redis client

	// Audit settings
	AuditService *services.AuditService // Optional: audit service for logging rate limit events
}

// NewRateLimiter creates a new rate limiter with configurable store backend
func NewRateLimiter(config RateLimitConfig) (gin.HandlerFunc, error) {
	// Create rate from requests per minute
	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  int64(config.RequestsPerMinute),
	}

	var store limiter.Store
	var err error

	switch config.StoreType {
	case RateLimitStoreRedis:
		// Redis client must be provided when using Redis store
		if config.RedisClient == nil {
			return nil, errors.New(
				"RedisClient is required when StoreType is redis (should be initialized in main.go)",
			)
		}

		// Create Redis store with provided client
		// *redis.Client implements redis.UniversalClient interface
		store, err = limiterRedis.NewStoreWithOptions(config.RedisClient, limiter.StoreOptions{
			Prefix:          "ratelimit",
			CleanUpInterval: config.CleanupInterval,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis store: %w", err)
		}

	case RateLimitStoreMemory:
		fallthrough
	default:
		// Create memory store
		store = memory.NewStore()
	}

	// Create limiter instance
	instance := limiter.New(store, rate)

	// Create Gin middleware with custom limit reached handler
	middleware := mgin.NewMiddleware(instance, mgin.WithLimitReachedHandler(func(c *gin.Context) {
		// Log rate limit exceeded event
		if config.AuditService != nil {
			// Extract user info if available
			var actorUserID, actorUsername string
			if userID, exists := c.Get("user_id"); exists {
				actorUserID = userID.(string)
			}
			if username, exists := c.Get("username"); exists {
				actorUsername = username.(string)
			}

			config.AuditService.Log(c.Request.Context(), services.AuditLogEntry{
				EventType:     models.EventRateLimitExceeded,
				Severity:      models.SeverityWarning,
				ActorUserID:   actorUserID,
				ActorUsername: actorUsername,
				Action:        "Rate limit exceeded",
				Details: models.AuditDetails{
					"endpoint":            c.Request.URL.Path,
					"requests_per_minute": config.RequestsPerMinute,
				},
				Success:       false,
				ErrorMessage:  "Too many requests",
				RequestPath:   c.Request.URL.Path,
				RequestMethod: c.Request.Method,
				UserAgent:     c.Request.UserAgent(),
			})
		}

		// Check if the request accepts HTML (browser request)
		acceptHeader := c.GetHeader("Accept")
		if strings.Contains(acceptHeader, "text/html") {
			// Render HTML error page for browser requests
			c.HTML(http.StatusTooManyRequests, "error.html", gin.H{
				"error":   "Rate Limit Exceeded",
				"message": "Too many requests. Please try again later.",
			})
		} else {
			// Return JSON error for API requests
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many requests. Please try again later.",
			})
		}
		c.Abort()
	}))

	return middleware, nil
}
