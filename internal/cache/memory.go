package cache

import (
	"context"
	"sync"
	"time"
)

type cacheItem struct {
	value     int64
	expiresAt time.Time
}

// MemoryCache implements Cache interface with in-memory storage.
// Uses lazy expiration (checks expiry on Get).
// Suitable for single-instance deployments.
type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
}

// NewMemoryCache creates a new memory cache instance.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string]cacheItem),
	}
}

// Get retrieves a value from cache.
func (m *MemoryCache) Get(ctx context.Context, key string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.items[key]
	if !exists {
		return 0, ErrCacheMiss
	}

	// Lazy expiration check
	if time.Now().After(item.expiresAt) {
		return 0, ErrCacheMiss
	}

	return item.value, nil
}

// Set stores a value in cache with TTL.
func (m *MemoryCache) Set(ctx context.Context, key string, value int64, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items[key] = cacheItem{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// GetWithFetch retrieves a value using cache-aside pattern.
// On cache miss, calls fetchFunc to get the value and stores it in cache.
func (m *MemoryCache) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (int64, error),
) (int64, error) {
	// Try cache first
	if value, err := m.Get(ctx, key); err == nil {
		return value, nil
	}

	// Cache miss - fetch from source
	value, err := fetchFunc(ctx, key)
	if err != nil {
		return 0, err
	}

	// Update cache (fire-and-forget, ignore errors)
	_ = m.Set(ctx, key, value, ttl)

	return value, nil
}

// MGet retrieves multiple values from cache.
func (m *MemoryCache) MGet(ctx context.Context, keys []string) (map[string]int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]int64)
	now := time.Now()

	for _, key := range keys {
		if item, exists := m.items[key]; exists && now.Before(item.expiresAt) {
			result[key] = item.value
		}
	}

	return result, nil
}

// MSet stores multiple values in cache with TTL.
func (m *MemoryCache) MSet(ctx context.Context, values map[string]int64, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := time.Now().Add(ttl)
	for key, value := range values {
		m.items[key] = cacheItem{
			value:     value,
			expiresAt: expiresAt,
		}
	}

	return nil
}

// Delete removes a key from cache.
func (m *MemoryCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.items, key)
	return nil
}

// Close cleans up resources.
func (m *MemoryCache) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items = make(map[string]cacheItem)
	return nil
}

// Health checks if the cache is healthy (always true for memory cache).
func (m *MemoryCache) Health(ctx context.Context) error {
	return nil
}
