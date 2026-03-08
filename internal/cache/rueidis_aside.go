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
	redisBase[T]
	asideClient rueidisaside.CacheAsideClient
	clientTTL   time.Duration
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
	asideClient, err := rueidisaside.NewClient(rueidisaside.ClientOption{
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

	client := asideClient.Client()

	// Test connection with provided context
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		asideClient.Close()
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return &RueidisAsideCache[T]{
		redisBase: redisBase[T]{
			client:    client,
			keyPrefix: keyPrefix,
			closeFunc: asideClient.Close,
		},
		asideClient: asideClient,
		clientTTL:   clientTTL,
	}, nil
}

// Get retrieves a value from Redis with client-side caching.
// Uses DoCache to leverage RESP3 client-side caching with automatic invalidation.
func (r *RueidisAsideCache[T]) Get(ctx context.Context, key string) (T, error) {
	// Use DoCache for client-side caching (RESP3 automatic invalidation)
	cmd := r.client.B().Get().Key(prefixedKey(r.keyPrefix, key)).Cache()
	resp := r.client.DoCache(ctx, cmd, r.clientTTL)

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
// This is an enhanced method that leverages rueidisaside's automatic cache management.
// The fetchFunc is called automatically on cache miss to populate the cache.
func (r *RueidisAsideCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	val, err := r.asideClient.Get(
		ctx,
		ttl,
		prefixedKey(r.keyPrefix, key),
		func(ctx context.Context, key string) (string, error) {
			// Call the provided fetch function to get data from source (e.g., database)
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

// MGet retrieves multiple values from Redis with client-side caching.
func (r *RueidisAsideCache[T]) MGet(ctx context.Context, keys []string) (map[string]T, error) {
	if len(keys) == 0 {
		return make(map[string]T), nil
	}

	// Use DoCache for client-side caching with MGET
	cmd := r.client.B().Mget().Key(prefixedKeys(r.keyPrefix, keys)...).Cache()
	resp := r.client.DoCache(ctx, cmd, r.clientTTL)

	if err := resp.Error(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	values, err := resp.ToArray()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return parseMultiGetResponse[T](keys, values), nil
}
