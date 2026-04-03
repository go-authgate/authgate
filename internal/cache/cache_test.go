package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryCache_GetSet(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	// Test Set and Get
	err := cache.Set(ctx, "test-key", 42, time.Minute)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	value, err := cache.Get(ctx, "test-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if value != 42 {
		t.Errorf("Expected value 42, got %d", value)
	}
}

func TestMemoryCache_GetMiss(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	_, err := cache.Get(ctx, "non-existent")
	if err != ErrCacheMiss {
		t.Errorf("Expected ErrCacheMiss, got %v", err)
	}
}

func TestMemoryCache_Expiration(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	// Set with very short TTL
	err := cache.Set(ctx, "expire-key", 100, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should be available immediately
	value, err := cache.Get(ctx, "expire-key")
	if err != nil {
		t.Fatalf("Get failed before expiration: %v", err)
	}
	if value != 100 {
		t.Errorf("Expected value 100, got %d", value)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired now
	_, err = cache.Get(ctx, "expire-key")
	if err != ErrCacheMiss {
		t.Errorf("Expected ErrCacheMiss after expiration, got %v", err)
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	// Set a value
	err := cache.Set(ctx, "delete-key", 123, time.Minute)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Verify it exists
	_, err = cache.Get(ctx, "delete-key")
	if err != nil {
		t.Fatalf("Get failed before delete: %v", err)
	}

	// Delete it
	err = cache.Delete(ctx, "delete-key")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Should not exist anymore
	_, err = cache.Get(ctx, "delete-key")
	if err != ErrCacheMiss {
		t.Errorf("Expected ErrCacheMiss after delete, got %v", err)
	}
}

func TestMemoryCache_Close(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	// Set some values
	_ = cache.Set(ctx, "key1", 1, time.Minute)
	_ = cache.Set(ctx, "key2", 2, time.Minute)

	// Close should clear all items
	err := cache.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// All items should be gone
	_, err = cache.Get(ctx, "key1")
	if err != ErrCacheMiss {
		t.Error("Expected cache to be cleared after Close")
	}
}

func TestMemoryCache_Health(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	err := cache.Health(ctx)
	if err != nil {
		t.Errorf("Health check should always succeed for memory cache, got: %v", err)
	}
}

func TestMemoryCache_Concurrent(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	// Test concurrent writes and reads
	done := make(chan bool, 20)

	// 10 writers
	for i := range 10 {
		go func(n int) {
			for j := range 100 {
				key := "concurrent-key"
				_ = cache.Set(ctx, key, int64(n*1000+j), time.Minute)
			}
			done <- true
		}(i)
	}

	// 10 readers
	for range 10 {
		go func() {
			for range 100 {
				_, _ = cache.Get(ctx, "concurrent-key")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 20 {
		<-done
	}

	// Should still be able to read
	_, err := cache.Get(ctx, "concurrent-key")
	if err != nil {
		t.Errorf("Cache corrupted after concurrent access: %v", err)
	}
}

func TestMemoryCache_GetWithFetch_CacheMiss(t *testing.T) {
	c := NewMemoryCache[int64]()
	ctx := context.Background()

	fetchCount := 0
	fetchFunc := func(ctx context.Context, key string) (int64, error) {
		fetchCount++
		return 42, nil
	}

	value, err := c.GetWithFetch(ctx, "key", time.Minute, fetchFunc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != 42 {
		t.Errorf("expected 42, got %d", value)
	}
	if fetchCount != 1 {
		t.Errorf("expected fetchFunc called once, got %d", fetchCount)
	}

	// Second call should use cache (fetchFunc not called again)
	value, err = c.GetWithFetch(ctx, "key", time.Minute, fetchFunc)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if value != 42 {
		t.Errorf("expected 42 on cache hit, got %d", value)
	}
	if fetchCount != 1 {
		t.Errorf("expected fetchFunc not called on cache hit, got %d calls", fetchCount)
	}
}

func TestMemoryCache_GetWithFetch_FetchError(t *testing.T) {
	c := NewMemoryCache[int64]()
	ctx := context.Background()

	expectedErr := errors.New("fetch failed")
	_, err := c.GetWithFetch(
		ctx,
		"key",
		time.Minute,
		func(ctx context.Context, key string) (int64, error) {
			return 0, expectedErr
		},
	)
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected fetch error, got %v", err)
	}
}

func TestMemoryCache_GetWithFetch_Concurrent(t *testing.T) {
	c := NewMemoryCache[int64]()
	ctx := context.Background()

	var fetchCount atomic.Int64
	fetchFunc := func(ctx context.Context, key string) (int64, error) {
		fetchCount.Add(1)
		return 99, nil
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			val, err := c.GetWithFetch(ctx, "shared-key", time.Minute, fetchFunc)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if val != 99 {
				t.Errorf("expected 99, got %d", val)
			}
		})
	}
	wg.Wait()
}

func TestMemoryCache_GetWithFetch_Expiration(t *testing.T) {
	c := NewMemoryCache[int64]()
	ctx := context.Background()

	fetchCount := 0
	fetchFunc := func(ctx context.Context, key string) (int64, error) {
		fetchCount++
		return int64(fetchCount * 10), nil
	}

	// First call — cache miss, fetchFunc invoked
	value, err := c.GetWithFetch(ctx, "expire-key", 50*time.Millisecond, fetchFunc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != 10 {
		t.Errorf("expected 10, got %d", value)
	}

	// Immediate second call — cache hit, fetchFunc must NOT be invoked again
	value, err = c.GetWithFetch(ctx, "expire-key", 50*time.Millisecond, fetchFunc)
	if err != nil {
		t.Fatalf("unexpected error on cache hit: %v", err)
	}
	if value != 10 {
		t.Errorf("expected cached value 10, got %d", value)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch before expiry, got %d", fetchCount)
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Call after expiry — cache miss, fetchFunc must be invoked again
	value, err = c.GetWithFetch(ctx, "expire-key", 50*time.Millisecond, fetchFunc)
	if err != nil {
		t.Fatalf("unexpected error after expiry: %v", err)
	}
	if value != 20 {
		t.Errorf("expected 20 after expiry, got %d", value)
	}
	if fetchCount != 2 {
		t.Errorf("expected 2 fetches after expiry, got %d", fetchCount)
	}
}

func TestMemoryCache_Reaper(t *testing.T) {
	// Short interval so the reaper fires within the test.
	c := NewMemoryCache[int64](20 * time.Millisecond)
	defer c.Close()
	ctx := context.Background()

	// Key1 expires before the reaper fires; key2 should survive.
	_ = c.Set(ctx, "key1", 1, 5*time.Millisecond)
	_ = c.Set(ctx, "key2", 2, time.Minute)

	// Wait for at least one reaper tick.
	time.Sleep(60 * time.Millisecond)

	if got := c.Len(); got != 1 {
		t.Errorf("expected 1 item after reaper eviction, got %d", got)
	}
	if _, err := c.Get(ctx, "key2"); err != nil {
		t.Errorf("key2 should survive reaper: %v", err)
	}
}

func TestMemoryCache_NoReaper(t *testing.T) {
	// Zero interval disables the reaper; expired items stay until lazily evicted.
	c := NewMemoryCache[int64](0)
	defer c.Close()
	ctx := context.Background()

	_ = c.Set(ctx, "key", 1, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	// Lazy eviction on Get should still report miss.
	if _, err := c.Get(ctx, "key"); err != ErrCacheMiss {
		t.Errorf("expected ErrCacheMiss on expired key, got %v", err)
	}
}
