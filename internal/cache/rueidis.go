package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/rueidis"
)

// Compile-time interface check.
var _ Cache[struct{}] = (*RueidisCache[struct{}])(nil)

// RueidisCache implements Cache interface using Redis via rueidis client.
// Suitable for multi-instance deployments where cache needs to be shared.
type RueidisCache[T any] struct {
	client    rueidis.Client
	keyPrefix string
}

// NewRueidisCache creates a new Redis cache instance using rueidis.
func NewRueidisCache[T any](
	ctx context.Context,
	addr, password string,
	db int,
	keyPrefix string,
) (*RueidisCache[T], error) {
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:  []string{addr},
		Password:     password,
		SelectDB:     db,
		DisableCache: true, // Basic mode without client-side caching
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create redis client: %w", err)
	}

	// Test connection with provided context
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return &RueidisCache[T]{
		client:    client,
		keyPrefix: keyPrefix,
	}, nil
}

// Get retrieves a value from Redis.
func (r *RueidisCache[T]) Get(ctx context.Context, key string) (T, error) {
	fullKey := r.keyPrefix + key

	cmd := r.client.B().Get().Key(fullKey).Build()
	resp := r.client.Do(ctx, cmd)

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

// Set stores a value in Redis with TTL.
func (r *RueidisCache[T]) Set(ctx context.Context, key string, value T, ttl time.Duration) error {
	fullKey := r.keyPrefix + key

	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	cmd := r.client.B().Set().
		Key(fullKey).
		Value(string(encoded)).
		Ex(ttl).
		Build()

	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// MGet retrieves multiple values from Redis.
func (r *RueidisCache[T]) MGet(ctx context.Context, keys []string) (map[string]T, error) {
	if len(keys) == 0 {
		return make(map[string]T), nil
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
func (r *RueidisCache[T]) MSet(ctx context.Context, values map[string]T, ttl time.Duration) error {
	if len(values) == 0 {
		return nil
	}

	// Use pipeline for multiple SET commands
	cmds := make(rueidis.Commands, 0, len(values))
	for key, value := range values {
		fullKey := r.keyPrefix + key

		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidValue, err)
		}

		cmd := r.client.B().Set().
			Key(fullKey).
			Value(string(encoded)).
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
func (r *RueidisCache[T]) Delete(ctx context.Context, key string) error {
	fullKey := r.keyPrefix + key

	cmd := r.client.B().Del().Key(fullKey).Build()
	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// Close closes the Redis connection.
func (r *RueidisCache[T]) Close() error {
	r.client.Close()
	return nil
}

// Health checks if Redis is reachable.
func (r *RueidisCache[T]) Health(ctx context.Context) error {
	cmd := r.client.B().Ping().Build()
	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}
	return nil
}

// GetWithFetch retrieves a value using the cache-aside pattern.
// On cache miss, fetchFunc is called and the result is stored in cache.
// No stampede protection is provided.
func (r *RueidisCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	if value, err := r.Get(ctx, key); err == nil {
		return value, nil
	}
	value, err := fetchFunc(ctx, key)
	if err != nil {
		var zero T
		return zero, err
	}
	_ = r.Set(ctx, key, value, ttl)
	return value, nil
}
