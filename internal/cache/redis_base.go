package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/rueidis"
)

// redisBase provides shared Set, MSet, Delete, Health, and Close
// implementations for Redis-backed caches.
type redisBase[T any] struct {
	client    rueidis.Client
	keyPrefix string
	closeFunc func()
}

// Set stores a value in Redis with TTL.
func (r *redisBase[T]) Set(ctx context.Context, key string, value T, ttl time.Duration) error {
	encoded, err := marshalValue(value)
	if err != nil {
		return err
	}

	cmd := r.client.B().Set().
		Key(prefixedKey(r.keyPrefix, key)).
		Value(encoded).
		Ex(ttl).
		Build()

	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// MSet stores multiple values in Redis with TTL.
func (r *redisBase[T]) MSet(ctx context.Context, values map[string]T, ttl time.Duration) error {
	if len(values) == 0 {
		return nil
	}

	cmds := make(rueidis.Commands, 0, len(values))
	for key, value := range values {
		encoded, err := marshalValue(value)
		if err != nil {
			return err
		}

		cmd := r.client.B().Set().
			Key(prefixedKey(r.keyPrefix, key)).
			Value(encoded).
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
func (r *redisBase[T]) Delete(ctx context.Context, key string) error {
	cmd := r.client.B().Del().Key(prefixedKey(r.keyPrefix, key)).Build()
	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}

	return nil
}

// Close closes the Redis connection.
func (r *redisBase[T]) Close() error {
	r.closeFunc()
	return nil
}

// Health checks if Redis is reachable.
func (r *redisBase[T]) Health(ctx context.Context) error {
	cmd := r.client.B().Ping().Build()
	if err := r.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
	}
	return nil
}
