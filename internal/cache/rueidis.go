package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/rueidis"
)

// RueidisCache implements Cache interface using Redis via rueidis client.
// Suitable for multi-instance deployments where cache needs to be shared.
type RueidisCache struct {
	client    rueidis.Client
	keyPrefix string
}

// NewRueidisCache creates a new Redis cache instance using rueidis.
func NewRueidisCache(addr, password string, db int, keyPrefix string) (*RueidisCache, error) {
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:  []string{addr},
		Password:     password,
		SelectDB:     db,
		DisableCache: true, // Basic mode without client-side caching
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create redis client: %w", err)
	}

	return &RueidisCache{
		client:    client,
		keyPrefix: keyPrefix,
	}, nil
}

// Get retrieves a value from Redis.
func (r *RueidisCache) Get(ctx context.Context, key string) (int64, error) {
	fullKey := r.keyPrefix + key

	cmd := r.client.B().Get().Key(fullKey).Build()
	resp := r.client.Do(ctx, cmd)

	if err := resp.Error(); err != nil {
		if rueidis.IsRedisNil(err) {
			return 0, ErrCacheMiss
		}
		return 0, fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	str, err := resp.ToString()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	value, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return value, nil
}

// Set stores a value in Redis with TTL.
func (r *RueidisCache) Set(ctx context.Context, key string, value int64, ttl time.Duration) error {
	fullKey := r.keyPrefix + key

	cmd := r.client.B().Set().
		Key(fullKey).
		Value(strconv.FormatInt(value, 10)).
		Ex(ttl).
		Build()

	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// GetWithFetch retrieves a value using cache-aside pattern.
// On cache miss, calls fetchFunc to get the value and stores it in cache.
func (r *RueidisCache) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (int64, error),
) (int64, error) {
	// Try cache first
	if value, err := r.Get(ctx, key); err == nil {
		return value, nil
	}
	// On cache errors (non-ErrCacheMiss), continue with fetch for graceful degradation

	// Cache miss - fetch from source
	value, err := fetchFunc(ctx, key)
	if err != nil {
		return 0, err
	}

	// Update cache (fire-and-forget, ignore errors)
	_ = r.Set(ctx, key, value, ttl)

	return value, nil
}

// MGet retrieves multiple values from Redis.
func (r *RueidisCache) MGet(ctx context.Context, keys []string) (map[string]int64, error) {
	if len(keys) == 0 {
		return make(map[string]int64), nil
	}

	// Build full keys
	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = r.keyPrefix + key
	}

	cmd := r.client.B().Mget().Key(fullKeys...).Build()
	resp := r.client.Do(ctx, cmd)

	if err := resp.Error(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	values, err := resp.ToArray()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	result := make(map[string]int64)
	for i, val := range values {
		if val.IsNil() {
			continue // Skip missing keys
		}

		str, err := val.ToString()
		if err != nil {
			continue // Skip invalid values
		}

		num, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			continue // Skip invalid numbers
		}

		result[keys[i]] = num
	}

	return result, nil
}

// MSet stores multiple values in Redis with TTL.
func (r *RueidisCache) MSet(ctx context.Context, values map[string]int64, ttl time.Duration) error {
	if len(values) == 0 {
		return nil
	}

	// Use pipeline for multiple SET commands
	cmds := make(rueidis.Commands, 0, len(values))
	for key, value := range values {
		fullKey := r.keyPrefix + key
		cmd := r.client.B().Set().
			Key(fullKey).
			Value(strconv.FormatInt(value, 10)).
			Ex(ttl).
			Build()
		cmds = append(cmds, cmd)
	}

	for _, resp := range r.client.DoMulti(ctx, cmds...) {
		if err := resp.Error(); err != nil {
			return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
		}
	}

	return nil
}

// Delete removes a key from Redis.
func (r *RueidisCache) Delete(ctx context.Context, key string) error {
	fullKey := r.keyPrefix + key

	cmd := r.client.B().Del().Key(fullKey).Build()
	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// Close closes the Redis connection.
func (r *RueidisCache) Close() error {
	r.client.Close()
	return nil
}

// Health checks if Redis is reachable.
func (r *RueidisCache) Health(ctx context.Context) error {
	cmd := r.client.B().Ping().Build()
	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}
	return nil
}
