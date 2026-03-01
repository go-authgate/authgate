package core

import (
	"context"
	"time"
)

// Cache[T] defines the primitive operations for a key-value cache.
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

	// GetWithFetch retrieves a value using the cache-aside pattern.
	// On cache miss, fetchFunc is called and the result is stored in cache.
	// Implementations may provide stampede protection (e.g. RueidisAsideCache).
	GetWithFetch(
		ctx context.Context,
		key string,
		ttl time.Duration,
		fetchFunc func(ctx context.Context, key string) (T, error),
	) (T, error)
}
