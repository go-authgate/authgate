package cache

import (
	"context"
	"sync"
	"time"

	"github.com/go-authgate/authgate/internal/core"

	"golang.org/x/sync/singleflight"
)

type cacheItem[T any] struct {
	value     T
	expiresAt time.Time
}

// Compile-time interface check.
var _ core.Cache[struct{}] = (*MemoryCache[struct{}])(nil)

// MemoryCache implements Cache interface with in-memory storage.
// Uses lazy expiration (checks expiry on Get) plus a background reaper
// that periodically evicts expired entries to prevent memory leaks.
// Suitable for single-instance deployments.
type MemoryCache[T any] struct {
	mu        sync.RWMutex
	items     map[string]cacheItem[T]
	sf        singleflight.Group
	stop      chan struct{}
	closeOnce sync.Once
}

// NewMemoryCache creates a new memory cache instance.
// An optional cleanup interval controls how often the background reaper
// evicts expired entries (default: 5 minutes). Pass a non-positive value
// to disable the reaper entirely and rely on lazy expiration in Get.
func NewMemoryCache[T any](cleanupInterval ...time.Duration) *MemoryCache[T] {
	interval := 5 * time.Minute
	enableReaper := true
	if len(cleanupInterval) > 0 {
		if cleanupInterval[0] > 0 {
			interval = cleanupInterval[0]
		} else {
			enableReaper = false
		}
	}
	m := &MemoryCache[T]{
		items: make(map[string]cacheItem[T]),
		stop:  make(chan struct{}),
	}
	if enableReaper {
		go m.reaper(interval)
	}
	return m
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

// Close stops the background reaper and cleans up resources.
// Safe to call multiple times concurrently.
func (m *MemoryCache[T]) Close() error {
	m.closeOnce.Do(func() {
		close(m.stop)
	})

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
// Uses singleflight to deduplicate concurrent fetches for the same key.
func (m *MemoryCache[T]) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (T, error),
) (T, error) {
	if value, err := m.Get(ctx, key); err == nil {
		return value, nil
	}

	// Cache miss: use singleflight to deduplicate concurrent fetches.
	// Run shared work under a non-canceling context so one caller's
	// cancellation does not abort the fetch for all other callers.
	resultCh := m.sf.DoChan(key, func() (any, error) {
		sharedCtx := context.WithoutCancel(ctx)
		// Re-check cache under singleflight (another goroutine may have populated it)
		if value, err := m.Get(sharedCtx, key); err == nil {
			return value, nil
		}
		value, err := fetchFunc(sharedCtx, key)
		if err != nil {
			return nil, err
		}
		_ = m.Set(sharedCtx, key, value, ttl)
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

// reaper periodically evicts expired entries to prevent memory leaks.
func (m *MemoryCache[T]) reaper(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.evictExpired()
		case <-m.stop:
			return
		}
	}
}

// evictExpired removes all expired entries from the cache.
func (m *MemoryCache[T]) evictExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, item := range m.items {
		if now.After(item.expiresAt) {
			delete(m.items, key)
		}
	}
}

// Len returns the number of items currently in the cache.
func (m *MemoryCache[T]) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}
