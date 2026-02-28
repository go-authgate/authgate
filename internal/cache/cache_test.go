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

func TestMemoryCache_MGetMSet(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	// Test MSet
	values := map[string]int64{
		"key1": 10,
		"key2": 20,
		"key3": 30,
	}
	err := cache.MSet(ctx, values, time.Minute)
	if err != nil {
		t.Fatalf("MSet failed: %v", err)
	}

	// Test MGet
	keys := []string{"key1", "key2", "key3", "non-existent"}
	result, err := cache.MGet(ctx, keys)
	if err != nil {
		t.Fatalf("MGet failed: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 results, got %d", len(result))
	}

	if result["key1"] != 10 || result["key2"] != 20 || result["key3"] != 30 {
		t.Errorf("MGet returned incorrect values: %v", result)
	}

	if _, exists := result["non-existent"]; exists {
		t.Error("MGet should not return non-existent keys")
	}
}

func TestMemoryCache_MGetExpiration(t *testing.T) {
	cache := NewMemoryCache[int64]()
	ctx := context.Background()

	// Set values with short TTL
	values := map[string]int64{
		"expire1": 100,
		"expire2": 200,
	}
	err := cache.MSet(ctx, values, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("MSet failed: %v", err)
	}

	// Should be available immediately
	result, err := cache.MGet(ctx, []string{"expire1", "expire2"})
	if err != nil {
		t.Fatalf("MGet failed before expiration: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("Expected 2 results before expiration, got %d", len(result))
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should return empty map after expiration
	result, err = cache.MGet(ctx, []string{"expire1", "expire2"})
	if err != nil {
		t.Fatalf("MGet failed after expiration: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected 0 results after expiration, got %d", len(result))
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
