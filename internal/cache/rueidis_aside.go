package cache

import (
	"context"
	"encoding/json"
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

// Get retrieves a value from Redis with client-side caching.
// Uses DoCache to leverage RESP3 client-side caching with automatic invalidation.
func (r *RueidisAsideCache[T]) Get(ctx context.Context, key string) (T, error) {
	fullKey := r.keyPrefix + key

	// Use DoCache for client-side caching (RESP3 automatic invalidation)
	cmd := r.client.Client().B().Get().Key(fullKey).Cache()
	resp := r.client.Client().DoCache(ctx, cmd, r.clientTTL)

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

	var value T
	if err := json.Unmarshal([]byte(str), &value); err != nil {
		var zero T
		return zero, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return value, nil
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
			encoded, err := json.Marshal(value)
			if err != nil {
				return "", err
			}
			return rueidis.BinaryString(encoded), nil
		},
	)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("failed to get with fetch: %w", err)
	}

	var result T
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		var zero T
		return zero, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	return result, nil
}

// Set stores a value in Redis with TTL.
func (r *RueidisAsideCache[T]) Set(
	ctx context.Context,
	key string,
	value T,
	ttl time.Duration,
) error {
	fullKey := r.keyPrefix + key

	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	// Use standard SET command via the underlying client
	cmd := r.client.Client().B().Set().
		Key(fullKey).
		Value(string(encoded)).
		Ex(ttl).
		Build()

	if err := r.client.Client().Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// MGet retrieves multiple values from Redis with client-side caching.
func (r *RueidisAsideCache[T]) MGet(ctx context.Context, keys []string) (map[string]T, error) {
	if len(keys) == 0 {
		return make(map[string]T), nil
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

	result := make(map[string]T)
	for i, val := range values {
		if val.IsNil() {
			continue // Skip missing keys
		}

		str, err := val.ToString()
		if err != nil {
			continue // Skip invalid values
		}

		var item T
		if err := json.Unmarshal([]byte(str), &item); err != nil {
			continue // Skip invalid values
		}

		result[keys[i]] = item
	}

	return result, nil
}

// MSet stores multiple values in Redis with TTL.
func (r *RueidisAsideCache[T]) MSet(
	ctx context.Context,
	values map[string]T,
	ttl time.Duration,
) error {
	if len(values) == 0 {
		return nil
	}

	// Use pipeline for multiple SET commands via the underlying client
	cmds := make(rueidis.Commands, 0, len(values))
	for key, value := range values {
		fullKey := r.keyPrefix + key

		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidValue, err)
		}

		cmd := r.client.Client().B().Set().
			Key(fullKey).
			Value(string(encoded)).
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
func (r *RueidisAsideCache[T]) Delete(ctx context.Context, key string) error {
	fullKey := r.keyPrefix + key

	cmd := r.client.Client().B().Del().Key(fullKey).Build()
	if err := r.client.Client().Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// Close closes the Redis connection.
func (r *RueidisAsideCache[T]) Close() error {
	r.client.Close()
	return nil
}

// Health checks if Redis is reachable.
func (r *RueidisAsideCache[T]) Health(ctx context.Context) error {
	cmd := r.client.Client().B().Ping().Build()
	if err := r.client.Client().Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}
	return nil
}
