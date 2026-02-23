package bootstrap

import (
	"context"
	"fmt"
	"log"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/middleware"
	"github.com/redis/go-redis/v9"
)

// initializeRateLimitRedisClient initializes the go-redis client for rate limiting.
// Returns nil if rate limiting is disabled or using memory store.
// Note: rate limiting must use go-redis because ulule/limiter depends on go-redis types.
func initializeRateLimitRedisClient(
	ctx context.Context,
	cfg *config.Config,
) (*redis.Client, error) {
	// Skip if rate limiting is disabled
	if !cfg.EnableRateLimit {
		return nil, nil //nolint:nilnil // redis client not needed in this configuration
	}

	// Skip if using memory store
	if cfg.RateLimitStore != string(middleware.RateLimitStoreRedis) {
		return nil, nil //nolint:nilnil // redis client not needed in this configuration
	}

	// Create go-redis client
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(ctx, cfg.RedisConnTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis at %s: %w", cfg.RedisAddr, err)
	}

	log.Printf(
		"Rate limiting Redis client initialized (address: %s, db: %d)",
		cfg.RedisAddr,
		cfg.RedisDB,
	)
	return client, nil
}
