package middleware

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create memory-based rate limiter (5 requests per minute)
	limiter, err := NewMemoryRateLimiter(5)
	require.NoError(t, err)
	require.NotNil(t, limiter)

	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// First requests should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited")
	assert.Contains(t, w.Body.String(), "rate_limit_exceeded")
}

func TestNewRateLimiter_MemoryStore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 10,
		StoreType:         RateLimitStoreMemory,
		CleanupInterval:   1 * time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, limiter)

	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Test basic functionality
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 2,
		StoreType:         RateLimitStoreMemory,
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Different IPs should have independent limits
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

	for _, ip := range ips {
		// Each IP can make 2 requests
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("X-Forwarded-For", ip)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d from IP %s should succeed", i+1, ip)
		}

		// Third request from this IP should be rate limited
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", ip)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(
			t,
			http.StatusTooManyRequests,
			w.Code,
			"Third request from IP %s should be rate limited",
			ip,
		)
	}
}

func TestRateLimiter_ErrorResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 1,
		StoreType:         RateLimitStoreMemory,
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.50")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should be rate limited with proper error
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.50")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "rate_limit_exceeded")
	assert.Contains(t, w.Body.String(), "Too many requests")
}

func TestNewRedisRateLimiter_InvalidAddress(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Try to connect to non-existent Redis
	limiter, err := NewRedisRateLimiter(10, "invalid-host:9999", "", 0)

	// Should fail to connect
	assert.Error(t, err)
	assert.Nil(t, limiter)
	assert.Contains(t, err.Error(), "failed to connect to Redis")
}

// TestNewRedisRateLimiter_Success tests Redis rate limiter with a real Redis instance
// This test is skipped by default and requires a Redis server running on localhost:6379
// To run: go test -run TestNewRedisRateLimiter_Success -tags=integration
func TestNewRedisRateLimiter_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gin.SetMode(gin.TestMode)

	// Try to create Redis rate limiter
	limiter, err := NewRedisRateLimiter(5, "localhost:6379", "", 0)
	// If Redis is not available, skip the test
	if err != nil {
		t.Skipf("Redis not available: %v", err)
		return
	}

	require.NotNil(t, limiter)

	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Generate unique IP to avoid conflicts with other tests
	testIP := "192.168.99." + time.Now().Format("150405")

	// Make requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", testIP)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", testIP)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request should be rate limited")
}

// TestRedisRateLimiter_MultiInstance simulates multiple pods sharing Redis
func TestRedisRateLimiter_MultiInstance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gin.SetMode(gin.TestMode)

	// Create two separate rate limiters (simulating two pods)
	limiter1, err1 := NewRedisRateLimiter(5, "localhost:6379", "", 0)
	limiter2, err2 := NewRedisRateLimiter(5, "localhost:6379", "", 0)

	if err1 != nil || err2 != nil {
		t.Skipf("Redis not available: %v %v", err1, err2)
		return
	}

	router1 := gin.New()
	router1.Use(limiter1)
	router1.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pod1"})
	})

	router2 := gin.New()
	router2.Use(limiter2)
	router2.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pod2"})
	})

	testIP := "192.168.88." + time.Now().Format("150405")

	// Make 3 requests to pod1
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", testIP)
		w := httptest.NewRecorder()
		router1.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Pod1 request %d should succeed", i+1)
	}

	// Make 2 requests to pod2 (should succeed, total = 5)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", testIP)
		w := httptest.NewRecorder()
		router2.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Pod2 request %d should succeed", i+1)
	}

	// Next request to either pod should be rate limited (total would be 6)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", testIP)
	w := httptest.NewRecorder()
	router1.ServeHTTP(w, req)

	assert.Equal(
		t,
		http.StatusTooManyRequests,
		w.Code,
		"Shared rate limit should be enforced across pods",
	)

	// Cleanup Redis keys
	ctx := context.Background()
	client := getRedisClientForTest()
	if client != nil {
		_ = client.Del(ctx, "ratelimit:"+testIP).Err()
	}
}

// Helper function to get Redis client for cleanup
func getRedisClientForTest() *redis.Client {
	// This is a simplified version for cleanup in tests
	// Returns nil if Redis is not available
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil
	}
	return client
}

// TestRateLimiter_HTMLErrorResponse tests that HTML error page is returned for browser requests
func TestRateLimiter_HTMLErrorResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter (1 request per minute)
	limiter, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 1,
		StoreType:         RateLimitStoreMemory,
	})
	require.NoError(t, err)

	router := gin.New()

	// Set up HTML template for error page
	tmpl := template.Must(template.New("error.html").Parse(`
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<h1>{{.error}}</h1>
<p>{{.message}}</p>
</body>
</html>`))
	router.SetHTMLTemplate(tmpl)

	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should be rate limited with HTML response
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "Rate Limit Exceeded")
	assert.Contains(t, w.Body.String(), "Too many requests. Please try again later.")
	assert.Contains(t, w.Body.String(), "<html>")
}

// TestRateLimiter_JSONErrorResponse tests that JSON error is returned for API requests
func TestRateLimiter_JSONErrorResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter (1 request per minute)
	limiter, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 1,
		StoreType:         RateLimitStoreMemory,
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.200")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should be rate limited with JSON response
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.200")
	req.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "rate_limit_exceeded")
	assert.Contains(t, w.Body.String(), "Too many requests")
	assert.NotContains(t, w.Body.String(), "<html>")
}

// TestRateLimiter_NoAcceptHeader tests default behavior with no Accept header
func TestRateLimiter_NoAcceptHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter (1 request per minute)
	limiter, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 1,
		StoreType:         RateLimitStoreMemory,
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(limiter)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.300")
	// No Accept header set
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should be rate limited with JSON response (default)
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.300")
	// No Accept header set
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "rate_limit_exceeded")
	assert.NotContains(t, w.Body.String(), "<html>")
}

// TestCreateRedisClient tests the CreateRedisClient helper function
func TestCreateRedisClient(t *testing.T) {
	// Test with invalid address
	client, err := CreateRedisClient("invalid-host:9999", "", 0)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to connect to Redis")

	// Test with valid address (if Redis is available)
	client, err = CreateRedisClient("localhost:6379", "", 0)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
		return
	}
	require.NotNil(t, client)
	assert.NotNil(t, client)

	// Verify connection works
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err = client.Ping(ctx).Err()
	assert.NoError(t, err)

	// Cleanup
	_ = client.Close()
}

// TestSharedRedisClient tests that multiple rate limiters can share a single Redis client
func TestSharedRedisClient(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gin.SetMode(gin.TestMode)

	// Create a shared Redis client
	sharedClient, err := CreateRedisClient("localhost:6379", "", 0)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
		return
	}
	defer sharedClient.Close()

	// Create two rate limiters sharing the same Redis client
	limiter1, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 5,
		StoreType:         RateLimitStoreRedis,
		RedisClient:       sharedClient,
		CleanupInterval:   1 * time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, limiter1)

	limiter2, err := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 10,
		StoreType:         RateLimitStoreRedis,
		RedisClient:       sharedClient,
		CleanupInterval:   1 * time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, limiter2)

	// Create two routers with different limiters
	router1 := gin.New()
	router1.Use(limiter1)
	router1.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "router1"})
	})

	router2 := gin.New()
	router2.Use(limiter2)
	router2.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "router2"})
	})

	testIP := "192.168.77." + time.Now().Format("150405")

	// Test router1 (5 req/min limit)
	for i := range 5 {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", testIP)
		w := httptest.NewRecorder()
		router1.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Router1 request %d should succeed", i+1)
	}

	// 6th request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", testIP)
	w := httptest.NewRecorder()
	router1.ServeHTTP(w, req)
	assert.Equal(
		t,
		http.StatusTooManyRequests,
		w.Code,
		"Router1 6th request should be rate limited",
	)

	// Test router2 with different IP (10 req/min limit)
	testIP2 := "192.168.78." + time.Now().Format("150405")
	for i := range 10 {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", testIP2)
		w := httptest.NewRecorder()
		router2.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Router2 request %d should succeed", i+1)
	}

	// 11th request should be rate limited
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", testIP2)
	w = httptest.NewRecorder()
	router2.ServeHTTP(w, req)
	assert.Equal(
		t,
		http.StatusTooManyRequests,
		w.Code,
		"Router2 11th request should be rate limited",
	)

	// Cleanup
	ctx := context.Background()
	_ = sharedClient.Del(ctx, "ratelimit:"+testIP).Err()
	_ = sharedClient.Del(ctx, "ratelimit:"+testIP2).Err()
}

// TestRateLimiter_MixedAcceptHeaders tests different Accept header variations
func TestRateLimiter_MixedAcceptHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name               string
		acceptHeader       string
		expectedJSON       bool
		expectedStatusCode int
	}{
		{
			name:               "Browser Accept header",
			acceptHeader:       "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			expectedJSON:       false,
			expectedStatusCode: http.StatusTooManyRequests,
		},
		{
			name:               "API JSON Accept",
			acceptHeader:       "application/json",
			expectedJSON:       true,
			expectedStatusCode: http.StatusTooManyRequests,
		},
		{
			name:               "API with wildcard",
			acceptHeader:       "*/*",
			expectedJSON:       true,
			expectedStatusCode: http.StatusTooManyRequests,
		},
		{
			name:               "Plain text",
			acceptHeader:       "text/plain",
			expectedJSON:       true,
			expectedStatusCode: http.StatusTooManyRequests,
		},
		{
			name:               "XML only",
			acceptHeader:       "application/xml",
			expectedJSON:       true,
			expectedStatusCode: http.StatusTooManyRequests,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create rate limiter (1 request per minute)
			limiter, err := NewRateLimiter(RateLimitConfig{
				RequestsPerMinute: 1,
				StoreType:         RateLimitStoreMemory,
			})
			require.NoError(t, err)

			router := gin.New()

			// Set up HTML template if needed
			if !tc.expectedJSON {
				tmpl := template.Must(template.New("error.html").Parse(`
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<h1>{{.error}}</h1>
<p>{{.message}}</p>
</body>
</html>`))
				router.SetHTMLTemplate(tmpl)
			}

			router.Use(limiter)
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "ok"})
			})

			// Generate unique IP for this test case
			testIP := "192.168.2." + string(rune(100+len(tc.name)))

			// First request succeeds
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("X-Forwarded-For", testIP)
			req.Header.Set("Accept", tc.acceptHeader)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)

			// Second request should be rate limited
			req = httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("X-Forwarded-For", testIP)
			req.Header.Set("Accept", tc.acceptHeader)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatusCode, w.Code)

			if tc.expectedJSON {
				assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
				assert.Contains(t, w.Body.String(), "rate_limit_exceeded")
				assert.NotContains(t, w.Body.String(), "<html>")
			} else {
				assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
				assert.Contains(t, w.Body.String(), "Rate Limit Exceeded")
				assert.Contains(t, w.Body.String(), "<html>")
			}
		})
	}
}
