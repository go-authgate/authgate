package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/services"
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
	RedisClient   *redis.Client // Optional: shared Redis client (recommended)
	RedisAddr     string        // Redis address (e.g., "localhost:6379")
	RedisPassword string        // Redis password (empty for no auth)
	RedisDB       int           // Redis database number (default: 0)

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
		var client *redis.Client

		// Use provided client or create new one
		if config.RedisClient != nil {
			client = config.RedisClient
		} else {
			// Create Redis client (backward compatibility)
			client = redis.NewClient(&redis.Options{
				Addr:     config.RedisAddr,
				Password: config.RedisPassword,
				DB:       config.RedisDB,
			})

			// Test connection
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := client.Ping(ctx).Err(); err != nil {
				return nil, fmt.Errorf(
					"failed to connect to Redis at %s: %w",
					config.RedisAddr,
					err,
				)
			}
		}

		// Create Redis store
		store, err = limiterRedis.NewStoreWithOptions(client, limiter.StoreOptions{
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

// NewMemoryRateLimiter creates an in-memory rate limiter (single instance)
func NewMemoryRateLimiter(requestsPerMinute int) (gin.HandlerFunc, error) {
	return NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: requestsPerMinute,
		StoreType:         RateLimitStoreMemory,
		CleanupInterval:   5 * time.Minute,
	})
}

// NewRedisRateLimiter creates a Redis-backed rate limiter (distributed, multi-pod)
func NewRedisRateLimiter(
	requestsPerMinute int,
	redisAddr, redisPassword string,
	redisDB int,
) (gin.HandlerFunc, error) {
	return NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: requestsPerMinute,
		StoreType:         RateLimitStoreRedis,
		RedisAddr:         redisAddr,
		RedisPassword:     redisPassword,
		RedisDB:           redisDB,
		CleanupInterval:   5 * time.Minute,
	})
}

// CreateRedisClient creates and tests a Redis client connection
func CreateRedisClient(redisAddr, redisPassword string, redisDB int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis at %s: %w", redisAddr, err)
	}

	return client, nil
}
