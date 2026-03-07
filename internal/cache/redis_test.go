package cache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/core"

	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

var (
	redisOnce      sync.Once
	redisAddr      string
	redisContainer *tcredis.RedisContainer
	redisSkipMsg   string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if redisContainer != nil {
		_ = redisContainer.Terminate(context.Background())
	}
	os.Exit(code)
}

// getRedisAddr returns the address of a shared Redis container.
// Starts the container on first call, reuses it on subsequent calls.
func getRedisAddr(t *testing.T) string {
	t.Helper()

	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	redisOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				redisSkipMsg = fmt.Sprintf("Docker not available (panic: %v)", r)
			}
		}()

		ctx := context.Background()
		container, err := tcredis.Run(ctx, "redis:7-alpine")
		if err != nil {
			redisSkipMsg = fmt.Sprintf("Docker not available (%v)", err)
			return
		}
		redisContainer = container

		host, err := container.Host(ctx)
		if err != nil {
			redisSkipMsg = fmt.Sprintf("failed to get Redis host: %v", err)
			return
		}
		port, err := container.MappedPort(ctx, "6379/tcp")
		if err != nil {
			redisSkipMsg = fmt.Sprintf("failed to get Redis port: %v", err)
			return
		}
		redisAddr = net.JoinHostPort(host, port.Port())
	})

	if redisSkipMsg != "" {
		t.Skipf("Skipping Redis test: %s", redisSkipMsg)
	}
	return redisAddr
}

// newRueidisCache creates a RueidisCache connected to the test Redis.
func newRueidisCache(t *testing.T, addr, prefix string) *RueidisCache[int64] {
	t.Helper()
	ctx := context.Background()
	c, err := NewRueidisCache[int64](ctx, addr, "", 0, prefix)
	if err != nil {
		t.Fatalf("NewRueidisCache failed: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// newRueidisAsideCache creates a RueidisAsideCache connected to the test Redis.
func newRueidisAsideCache(t *testing.T, addr, prefix string) *RueidisAsideCache[int64] {
	t.Helper()
	ctx := context.Background()
	c, err := NewRueidisAsideCache[int64](ctx, addr, "", 0, prefix, 30*time.Second, 8)
	if err != nil {
		t.Fatalf("NewRueidisAsideCache failed: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// cacheTestSuite runs the full test suite against any core.Cache[int64] implementation.
func cacheTestSuite(t *testing.T, name string, newCache func(t *testing.T, prefix string) core.Cache[int64]) {
	t.Run(name+"/GetSet", func(t *testing.T) {
		c := newCache(t, "gs:")
		ctx := context.Background()

		err := c.Set(ctx, "test-key", 42, time.Minute)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		value, err := c.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if value != 42 {
			t.Errorf("expected 42, got %d", value)
		}
	})

	t.Run(name+"/GetMiss", func(t *testing.T) {
		c := newCache(t, "gm:")
		ctx := context.Background()

		_, err := c.Get(ctx, "non-existent")
		if !errors.Is(err, ErrCacheMiss) {
			t.Errorf("expected ErrCacheMiss, got %v", err)
		}
	})

	t.Run(name+"/Expiration", func(t *testing.T) {
		c := newCache(t, "exp:")
		ctx := context.Background()

		err := c.Set(ctx, "expire-key", 100, time.Second)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		value, err := c.Get(ctx, "expire-key")
		if err != nil {
			t.Fatalf("Get failed before expiration: %v", err)
		}
		if value != 100 {
			t.Errorf("expected 100, got %d", value)
		}

		// Wait for Redis TTL expiration
		time.Sleep(1500 * time.Millisecond)

		_, err = c.Get(ctx, "expire-key")
		if !errors.Is(err, ErrCacheMiss) {
			t.Errorf("expected ErrCacheMiss after expiration, got %v", err)
		}
	})

	t.Run(name+"/MGetMSet", func(t *testing.T) {
		c := newCache(t, "mm:")
		ctx := context.Background()

		values := map[string]int64{
			"key1": 10,
			"key2": 20,
			"key3": 30,
		}
		err := c.MSet(ctx, values, time.Minute)
		if err != nil {
			t.Fatalf("MSet failed: %v", err)
		}

		keys := []string{"key1", "key2", "key3", "non-existent"}
		result, err := c.MGet(ctx, keys)
		if err != nil {
			t.Fatalf("MGet failed: %v", err)
		}

		if len(result) != 3 {
			t.Errorf("expected 3 results, got %d", len(result))
		}
		if result["key1"] != 10 || result["key2"] != 20 || result["key3"] != 30 {
			t.Errorf("MGet returned incorrect values: %v", result)
		}
		if _, exists := result["non-existent"]; exists {
			t.Error("MGet should not return non-existent keys")
		}
	})

	t.Run(name+"/MGetEmpty", func(t *testing.T) {
		c := newCache(t, "me:")
		ctx := context.Background()

		result, err := c.MGet(ctx, []string{})
		if err != nil {
			t.Fatalf("MGet with empty keys failed: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty result, got %v", result)
		}
	})

	t.Run(name+"/MSetEmpty", func(t *testing.T) {
		c := newCache(t, "mse:")
		ctx := context.Background()

		err := c.MSet(ctx, map[string]int64{}, time.Minute)
		if err != nil {
			t.Fatalf("MSet with empty values failed: %v", err)
		}
	})

	t.Run(name+"/Delete", func(t *testing.T) {
		c := newCache(t, "del:")
		ctx := context.Background()

		err := c.Set(ctx, "delete-key", 123, time.Minute)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		_, err = c.Get(ctx, "delete-key")
		if err != nil {
			t.Fatalf("Get failed before delete: %v", err)
		}

		err = c.Delete(ctx, "delete-key")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = c.Get(ctx, "delete-key")
		if !errors.Is(err, ErrCacheMiss) {
			t.Errorf("expected ErrCacheMiss after delete, got %v", err)
		}
	})

	t.Run(name+"/DeleteNonExistent", func(t *testing.T) {
		c := newCache(t, "dne:")
		ctx := context.Background()

		err := c.Delete(ctx, "does-not-exist")
		if err != nil {
			t.Errorf("Delete non-existent key should not error, got %v", err)
		}
	})

	t.Run(name+"/Health", func(t *testing.T) {
		c := newCache(t, "h:")
		ctx := context.Background()

		err := c.Health(ctx)
		if err != nil {
			t.Errorf("Health check failed: %v", err)
		}
	})

	t.Run(name+"/Overwrite", func(t *testing.T) {
		c := newCache(t, "ow:")
		ctx := context.Background()

		_ = c.Set(ctx, "key", 1, time.Minute)
		_ = c.Set(ctx, "key", 2, time.Minute)

		value, err := c.Get(ctx, "key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if value != 2 {
			t.Errorf("expected overwritten value 2, got %d", value)
		}
	})

	t.Run(name+"/KeyPrefix", func(t *testing.T) {
		c1 := newCache(t, "ns1:")
		c2 := newCache(t, "ns2:")
		ctx := context.Background()

		_ = c1.Set(ctx, "key", 100, time.Minute)
		_ = c2.Set(ctx, "key", 200, time.Minute)

		v1, err := c1.Get(ctx, "key")
		if err != nil {
			t.Fatalf("c1 Get failed: %v", err)
		}
		v2, err := c2.Get(ctx, "key")
		if err != nil {
			t.Fatalf("c2 Get failed: %v", err)
		}

		if v1 != 100 {
			t.Errorf("expected c1 value 100, got %d", v1)
		}
		if v2 != 200 {
			t.Errorf("expected c2 value 200, got %d", v2)
		}
	})

	t.Run(name+"/GetWithFetch_CacheMiss", func(t *testing.T) {
		c := newCache(t, "gwf:")
		ctx := context.Background()

		var fetchCount atomic.Int32
		fetchFunc := func(ctx context.Context, key string) (int64, error) {
			fetchCount.Add(1)
			return 42, nil
		}

		value, err := c.GetWithFetch(ctx, "key", time.Minute, fetchFunc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if value != 42 {
			t.Errorf("expected 42, got %d", value)
		}
		if fetchCount.Load() != 1 {
			t.Errorf("expected fetchFunc called once, got %d", fetchCount.Load())
		}

		// Allow client-side cache invalidation to propagate (for RESP3 caches)
		time.Sleep(50 * time.Millisecond)

		// Second call should use cache
		value, err = c.GetWithFetch(ctx, "key", time.Minute, fetchFunc)
		if err != nil {
			t.Fatalf("unexpected error on second call: %v", err)
		}
		if value != 42 {
			t.Errorf("expected 42 on cache hit, got %d", value)
		}
		if fetchCount.Load() != 1 {
			t.Errorf("expected fetchFunc not called on cache hit, got %d calls", fetchCount.Load())
		}
	})

	t.Run(name+"/GetWithFetch_FetchError", func(t *testing.T) {
		c := newCache(t, "gwfe:")
		ctx := context.Background()

		expectedErr := errors.New("fetch failed")
		_, err := c.GetWithFetch(
			ctx, "key", time.Minute,
			func(ctx context.Context, key string) (int64, error) {
				return 0, expectedErr
			},
		)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run(name+"/GetWithFetch_Concurrent", func(t *testing.T) {
		c := newCache(t, "gwfc:")
		ctx := context.Background()

		var fetchCount atomic.Int64
		fetchFunc := func(ctx context.Context, key string) (int64, error) {
			fetchCount.Add(1)
			return 99, nil
		}

		var wg sync.WaitGroup
		for range 20 {
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
	})

	t.Run(name+"/Concurrent", func(t *testing.T) {
		c := newCache(t, "conc:")
		ctx := context.Background()

		var wg sync.WaitGroup

		// 10 writers
		for i := range 10 {
			n := i
			wg.Go(func() {
				for j := range 50 {
					_ = c.Set(ctx, "concurrent-key", int64(n*1000+j), time.Minute)
				}
			})
		}

		// 10 readers
		for range 10 {
			wg.Go(func() {
				for range 50 {
					_, _ = c.Get(ctx, "concurrent-key")
				}
			})
		}

		wg.Wait()

		_, err := c.Get(ctx, "concurrent-key")
		if err != nil {
			t.Errorf("cache corrupted after concurrent access: %v", err)
		}
	})
}

func TestRueidisCache(t *testing.T) {
	addr := getRedisAddr(t)

	cacheTestSuite(t, "RueidisCache", func(t *testing.T, prefix string) core.Cache[int64] {
		return newRueidisCache(t, addr, prefix)
	})
}

func TestRueidisAsideCache(t *testing.T) {
	addr := getRedisAddr(t)

	cacheTestSuite(t, "RueidisAsideCache", func(t *testing.T, prefix string) core.Cache[int64] {
		return newRueidisAsideCache(t, addr, prefix)
	})
}

func TestNewRueidisCache_InvalidAddr(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := NewRueidisCache[int64](ctx, "invalid-host:1", "", 0, "test:")
	if err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}
}

func TestNewRueidisAsideCache_InvalidAddr(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := NewRueidisAsideCache[int64](ctx, "invalid-host:1", "", 0, "test:", 30*time.Second, 8)
	if err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}
}
