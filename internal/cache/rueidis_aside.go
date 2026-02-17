package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidisaside"
)

// RueidisAsideCache implements Cache interface using rueidisaside for cache-aside pattern.
// Uses rueidis' automatic client-side caching with RESP3 protocol for cache invalidation.
// Suitable for high-load multi-instance deployments (5+ pods).
type RueidisAsideCache struct {
	client    rueidisaside.CacheAsideClient
	keyPrefix string
	clientTTL time.Duration
}

// NewRueidisAsideCache creates a new Redis cache with client-side caching using rueidisaside.
// clientTTL is the local cache TTL (e.g., 30s). Redis will automatically invalidate
// the local cache when keys change.
func NewRueidisAsideCache(
	addr, password string,
	db int,
	keyPrefix string,
	clientTTL time.Duration,
) (*RueidisAsideCache, error) {
	client, err := rueidisaside.NewClient(rueidisaside.ClientOption{
		ClientOption: rueidis.ClientOption{
			InitAddress:  []string{addr},
			Password:     password,
			SelectDB:     db,
			DisableCache: false, // Enable client-side caching
			// Client-side cache configuration
			CacheSizeEachConn: 128 * 1024 * 1024, // 128MB per connection
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rueidisaside client: %w", err)
	}

	return &RueidisAsideCache{
		client:    client,
		keyPrefix: keyPrefix,
		clientTTL: clientTTL,
	}, nil
}

// Get retrieves a value from Redis with client-side caching.
// For rueidisaside, this method returns ErrCacheMiss to maintain interface compatibility.
// The wrapper layer (MetricsCacheWrapper) will handle the fetch logic and call Set.
func (r *RueidisAsideCache) Get(ctx context.Context, key string) (int64, error) {
	fullKey := r.keyPrefix + key

	// Use rueidisaside.Get with a fetch function that returns ErrCacheMiss
	// This allows the client-side cache to work while maintaining our interface
	val, err := r.client.Get(
		ctx,
		r.clientTTL,
		fullKey,
		func(ctx context.Context, key string) (val string, err error) {
			// Return empty to indicate cache miss - wrapper will fetch from DB and call Set
			return "", ErrCacheMiss
		},
	)
	if err != nil {
		if err == ErrCacheMiss {
			return 0, ErrCacheMiss
		}
		return 0, fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	if val == "" {
		return 0, ErrCacheMiss
	}

	value, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return value, nil
}

// GetWithFetch retrieves a value using rueidisaside's cache-aside pattern.
// This is an enhanced method that leverages rueidisaside's automatic cache management.
// The fetchFunc is called automatically on cache miss to populate the cache.
func (r *RueidisAsideCache) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (int64, error),
) (int64, error) {
	fullKey := r.keyPrefix + key

	val, err := r.client.Get(
		ctx,
		ttl,
		fullKey,
		func(ctx context.Context, key string) (string, error) {
			// Call the provided fetch function to get data from source (e.g., database)
			value, err := fetchFunc(ctx, key)
			if err != nil {
				return "", err
			}
			return strconv.FormatInt(value, 10), nil
		},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get with fetch: %w", err)
	}

	value, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return value, nil
}

// Set stores a value in Redis with TTL.
func (r *RueidisAsideCache) Set(
	ctx context.Context,
	key string,
	value int64,
	ttl time.Duration,
) error {
	fullKey := r.keyPrefix + key

	// Use standard SET command via the underlying client
	cmd := r.client.Client().B().Set().
		Key(fullKey).
		Value(strconv.FormatInt(value, 10)).
		Ex(ttl).
		Build()

	if err := r.client.Client().Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// MGet retrieves multiple values from Redis with client-side caching.
func (r *RueidisAsideCache) MGet(ctx context.Context, keys []string) (map[string]int64, error) {
	if len(keys) == 0 {
		return make(map[string]int64), nil
	}

	// Build full keys
	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = r.keyPrefix + key
	}

	// Use standard MGET command via the underlying client
	cmd := r.client.Client().B().Mget().Key(fullKeys...).Cache()
	resp := r.client.Client().DoCache(ctx, cmd, r.clientTTL)

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
func (r *RueidisAsideCache) MSet(
	ctx context.Context,
	values map[string]int64,
	ttl time.Duration,
) error {
	if len(values) == 0 {
		return nil
	}

	// Use pipeline for multiple SET commands via the underlying client
	cmds := make(rueidis.Commands, 0, len(values))
	for key, value := range values {
		fullKey := r.keyPrefix + key
		cmd := r.client.Client().B().Set().
			Key(fullKey).
			Value(strconv.FormatInt(value, 10)).
			Ex(ttl).
			Build()
		cmds = append(cmds, cmd)
	}

	for _, resp := range r.client.Client().DoMulti(ctx, cmds...) {
		if err := resp.Error(); err != nil {
			return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
		}
	}

	return nil
}

// Delete removes a key from Redis.
func (r *RueidisAsideCache) Delete(ctx context.Context, key string) error {
	fullKey := r.keyPrefix + key

	cmd := r.client.Client().B().Del().Key(fullKey).Build()
	if err := r.client.Client().Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// Close closes the Redis connection.
func (r *RueidisAsideCache) Close() error {
	r.client.Close()
	return nil
}

// Health checks if Redis is reachable.
func (r *RueidisAsideCache) Health(ctx context.Context) error {
	cmd := r.client.Client().B().Ping().Build()
	if err := r.client.Client().Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}
	return nil
}
