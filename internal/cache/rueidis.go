package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-authgate/authgate/internal/core"

	"github.com/redis/rueidis"
	"golang.org/x/sync/singleflight"
)

// Compile-time interface check.
var _ core.Cache[struct{}] = (*RueidisCache[struct{}])(nil)

// RueidisCache implements Cache interface using Redis via rueidis client.
// Suitable for multi-instance deployments where cache needs to be shared.
type RueidisCache[T any] struct {
	redisBase[T]
	sf singleflight.Group
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
		redisBase: redisBase[T]{
			client:    client,
			keyPrefix: keyPrefix,
			closeFunc: client.Close,
		},
	}, nil
}

// Get retrieves a value from Redis.
func (r *RueidisCache[T]) Get(ctx context.Context, key string) (T, error) {
	cmd := r.client.B().Get().Key(prefixedKey(r.keyPrefix, key)).Build()
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

	return unmarshalValue[T](str)
}

// GetWithFetch retrieves a value using the cache-aside pattern.
// On cache miss, fetchFunc is called and the result is stored in cache.
// Uses singleflight to deduplicate concurrent fetches for the same key.
func (r *RueidisCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	if value, err := r.Get(ctx, key); err == nil {
		return value, nil
	}

	// Cache miss: use singleflight to deduplicate concurrent fetches.
	// Run shared work under a non-canceling context so one caller's
	// cancellation does not fail all waiters for the same key.
	resultCh := r.sf.DoChan(key, func() (any, error) {
		sharedCtx := context.WithoutCancel(ctx)
		// Re-check cache under singleflight (another goroutine may have populated it)
		if value, err := r.Get(sharedCtx, key); err == nil {
			return value, nil
		}
		value, err := fetchFunc(sharedCtx, key)
		if err != nil {
			return nil, err
		}
		_ = r.Set(sharedCtx, key, value, ttl)
		return value, nil
	})

	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case res := <-resultCh:
		if res.Err != nil {
			var zero T
			return zero, res.Err
		}
		return res.Val.(T), nil
	}
}
