package cache

import (
	"context"
	"sync"
	"time"

	"github.com/go-authgate/authgate/internal/core"
)

type cacheItem[T any] struct {
	value     T
	expiresAt time.Time
}

// Compile-time interface check.
var _ core.Cache[struct{}] = (*MemoryCache[struct{}])(nil)

// MemoryCache implements Cache interface with in-memory storage.
// Uses lazy expiration (checks expiry on Get).
// Suitable for single-instance deployments.
type MemoryCache[T any] struct {
	mu    sync.RWMutex
	items map[string]cacheItem[T]
}

// NewMemoryCache creates a new memory cache instance.
func NewMemoryCache[T any]() *MemoryCache[T] {
	return &MemoryCache[T]{
		items: make(map[string]cacheItem[T]),
	}
}

// Get retrieves a value from cache.
func (m *MemoryCache[T]) Get(ctx context.Context, key string) (T, error) {
	m.mu.RLock()
	item, exists := m.items[key]
	m.mu.RUnlock()

	if !exists {
		var zero T
		return zero, ErrCacheMiss
	}

	if time.Now().After(item.expiresAt) {
		// Lazily remove expired entry
		m.mu.Lock()
		// Re-check under write lock to avoid deleting a freshly-updated entry.
		if current, ok := m.items[key]; ok {
			if time.Now().After(current.expiresAt) {
				delete(m.items, key)
			}
		}
		m.mu.Unlock()
		var zero T
		return zero, ErrCacheMiss
	}

	return item.value, nil
}

// Set stores a value in cache with TTL.
func (m *MemoryCache[T]) Set(ctx context.Context, key string, value T, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items[key] = cacheItem[T]{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// Delete removes a key from cache.
func (m *MemoryCache[T]) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.items, key)
	return nil
}

// Close cleans up resources.
func (m *MemoryCache[T]) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items = make(map[string]cacheItem[T])
	return nil
}

// Health checks if the cache is healthy (always true for memory cache).
func (m *MemoryCache[T]) Health(ctx context.Context) error {
	return nil
}

// GetWithFetch retrieves a value using the cache-aside pattern.
// On cache miss, fetchFunc is called and the result is stored in cache.
// No stampede protection is provided (single-instance memory cache).
func (m *MemoryCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	return fetchThrough(ctx, key, ttl, m.Get, m.Set, fetchFunc)
}
