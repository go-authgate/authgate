package cache

import (
	"context"
	"time"
)

// Cache defines the primitive operations for a key-value cache.
// T is the type of value stored in the cache (e.g. int64, string, or a struct).
type Cache[T any] interface {
	// Get retrieves a single value from cache.
	// Returns ErrCacheMiss if the key does not exist or has expired.
	Get(ctx context.Context, key string) (T, error)

	// Set stores a single value in cache with TTL
	Set(ctx context.Context, key string, value T, ttl time.Duration) error

	// MGet retrieves multiple values from cache.
	// Returns a map of key->value for keys that exist and have not expired.
	MGet(ctx context.Context, keys []string) (map[string]T, error)

	// MSet stores multiple values in cache with TTL
	MSet(ctx context.Context, values map[string]T, ttl time.Duration) error

	// Delete removes a key from cache
	Delete(ctx context.Context, key string) error

	// Close closes the cache connection
	Close() error

	// Health checks if the cache is healthy
	Health(ctx context.Context) error
}

// CacheWithFetch extends Cache with an optimized cache-aside operation.
// Implementations that can provide stampede protection (e.g. RueidisAsideCache)
// should implement this interface. Callers should prefer this over the generic
// GetWithFetch helper when available, via type assertion.
type CacheWithFetch[T any] interface {
	Cache[T]

	// GetWithFetch retrieves a value using an optimized cache-aside pattern.
	// On cache miss, fetchFunc is called exactly once even under concurrent load,
	// and the result is stored in cache automatically.
	GetWithFetch(
		ctx context.Context,
		key string,
		ttl time.Duration,
		fetchFunc func(ctx context.Context, key string) (T, error),
	) (T, error)
}

// GetWithFetch is a generic cache-aside helper for any Cache implementation.
// On cache miss it calls fetchFunc, stores the result, and returns it.
// Use this when the cache does not implement CacheWithFetch.
// Note: does not provide stampede protection under concurrent load.
func GetWithFetch[T any](
	ctx context.Context,
	c Cache[T],
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	if value, err := c.Get(ctx, key); err == nil {
		return value, nil
	}

	value, err := fetchFunc(ctx, key)
	if err != nil {
		var zero T
		return zero, err
	}

	_ = c.Set(ctx, key, value, ttl)
	return value, nil
}
