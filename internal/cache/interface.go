package cache

import (
	"context"
	"time"
)

// Cache defines the interface for caching metrics data.
// All implementations should store int64 values (counts) for simplicity.
type Cache interface {
	// Get retrieves a single value from cache
	Get(ctx context.Context, key string) (int64, error)

	// Set stores a single value in cache with TTL
	Set(ctx context.Context, key string, value int64, ttl time.Duration) error

	// MGet retrieves multiple values from cache
	// Returns a map of key->value for keys that exist
	MGet(ctx context.Context, keys []string) (map[string]int64, error)

	// MSet stores multiple values in cache with TTL
	MSet(ctx context.Context, values map[string]int64, ttl time.Duration) error

	// Delete removes a key from cache
	Delete(ctx context.Context, key string) error

	// Close closes the cache connection
	Close() error

	// Health checks if the cache is healthy
	Health(ctx context.Context) error
}
