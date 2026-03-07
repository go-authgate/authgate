package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-authgate/authgate/internal/core"

	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidisaside"
)

// Compile-time interface check.
var _ core.Cache[struct{}] = (*RueidisAsideCache[struct{}])(nil)

// RueidisAsideCache implements Cache interface using rueidisaside for cache-aside pattern.
// Uses rueidis' automatic client-side caching with RESP3 protocol for cache invalidation.
// Suitable for high-load multi-instance deployments (5+ pods).
type RueidisAsideCache[T any] struct {
	client    rueidisaside.CacheAsideClient
	keyPrefix string
	clientTTL time.Duration
}

// NewRueidisAsideCache creates a new Redis cache with client-side caching using rueidisaside.
// clientTTL is the local cache TTL (e.g., 30s). Redis will automatically invalidate
// the local cache when keys change.
// cacheSizeMB is the client-side cache size per connection in megabytes.
// Note: Rueidis uses connection pooling (typically ~10 connections based on GOMAXPROCS),
// so total memory usage will be cacheSizeMB * number_of_connections.
func NewRueidisAsideCache[T any](
	ctx context.Context,
	addr, password string,
	db int,
	keyPrefix string,
	clientTTL time.Duration,
	cacheSizeMB int,
) (*RueidisAsideCache[T], error) {
	cacheSizeBytes := cacheSizeMB * 1024 * 1024
	client, err := rueidisaside.NewClient(rueidisaside.ClientOption{
		ClientOption: rueidis.ClientOption{
			InitAddress:  []string{addr},
			Password:     password,
			SelectDB:     db,
			DisableCache: false, // Enable client-side caching
			// Client-side cache configuration
			CacheSizeEachConn: cacheSizeBytes,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rueidisaside client: %w", err)
	}

	// Test connection with provided context
	if err := client.Client().Do(ctx, client.Client().B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return &RueidisAsideCache[T]{
		client:    client,
		keyPrefix: keyPrefix,
		clientTTL: clientTTL,
	}, nil
}

// Get retrieves a value from Redis.
// Uses standard Do (not DoCache) to ensure immediate consistency after Set/Delete.
// Client-side caching is provided through GetWithFetch and MGet instead.
func (r *RueidisAsideCache[T]) Get(ctx context.Context, key string) (T, error) {
	cmd := r.client.Client().B().Get().Key(prefixedKey(r.keyPrefix, key)).Build()
	resp := r.client.Client().Do(ctx, cmd)

	if err := resp.Error(); err != nil {
		var zero T
		if rueidis.IsRedisNil(err) {
			return zero, ErrCacheMiss
		}
		return zero, fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	str, err := resp.ToString()
	if err != nil {
		var zero T
		return zero, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return unmarshalValue[T](str)
}

// GetWithFetch retrieves a value using rueidisaside's cache-aside pattern.
// This leverages rueidisaside's automatic cache management with stampede protection.
// The fetchFunc is called automatically on cache miss to populate the cache.
func (r *RueidisAsideCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	val, err := r.client.Get(
		ctx,
		ttl,
		prefixedKey(r.keyPrefix, key),
		func(ctx context.Context, key string) (string, error) {
			value, err := fetchFunc(ctx, key)
			if err != nil {
				return "", err
			}
			return marshalValue(value)
		},
	)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("failed to get with fetch: %w", err)
	}

	return unmarshalValue[T](val)
}

// Set stores a value in Redis with TTL.
func (r *RueidisAsideCache[T]) Set(ctx context.Context, key string, value T, ttl time.Duration) error {
	return redisSet(ctx, r.client.Client(), r.keyPrefix, key, value, ttl)
}

// MGet retrieves multiple values from Redis with client-side caching.
func (r *RueidisAsideCache[T]) MGet(ctx context.Context, keys []string) (map[string]T, error) {
	if len(keys) == 0 {
		return make(map[string]T), nil
	}

	cmd := r.client.Client().B().Mget().Key(prefixedKeys(r.keyPrefix, keys)...).Cache()
	resp := r.client.Client().DoCache(ctx, cmd, r.clientTTL)

	if err := resp.Error(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	values, err := resp.ToArray()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return parseMultiGetResponse[T](keys, values), nil
}

// MSet stores multiple values in Redis with TTL.
func (r *RueidisAsideCache[T]) MSet(ctx context.Context, values map[string]T, ttl time.Duration) error {
	return redisMSet(ctx, r.client.Client(), r.keyPrefix, values, ttl)
}

// Delete removes a key from Redis.
func (r *RueidisAsideCache[T]) Delete(ctx context.Context, key string) error {
	return redisDelete(ctx, r.client.Client(), r.keyPrefix, key)
}

// Close closes the Redis connection.
func (r *RueidisAsideCache[T]) Close() error {
	r.client.Close()
	return nil
}

// Health checks if Redis is reachable.
func (r *RueidisAsideCache[T]) Health(ctx context.Context) error {
	return redisHealth(ctx, r.client.Client())
}
