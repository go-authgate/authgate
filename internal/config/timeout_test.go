package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestDefaultTimeoutValues verifies that timeout configurations have sensible defaults
func TestDefaultTimeoutValues(t *testing.T) {
	cfg := Load()

	// Database timeout
	assert.Equal(t, 30*time.Second, cfg.DBInitTimeout, "DB init timeout should be 30s")
	assert.Equal(t, 5*time.Second, cfg.DBCloseTimeout, "DB close timeout should be 5s")

	// Redis timeouts
	assert.Equal(t, 5*time.Second, cfg.RedisConnTimeout, "Redis connection timeout should be 5s")
	assert.Equal(t, 5*time.Second, cfg.RedisCloseTimeout, "Redis close timeout should be 5s")

	// Cache timeouts
	assert.Equal(t, 5*time.Second, cfg.CacheInitTimeout, "Cache init timeout should be 5s")
	assert.Equal(t, 5*time.Second, cfg.CacheCloseTimeout, "Cache close timeout should be 5s")

	// Server shutdown timeouts
	assert.Equal(
		t,
		5*time.Second,
		cfg.ServerShutdownTimeout,
		"Server shutdown timeout should be 5s",
	)
	assert.Equal(
		t,
		10*time.Second,
		cfg.AuditShutdownTimeout,
		"Audit shutdown timeout should be 10s",
	)
}

// TestTimeoutConfigurationFromEnv verifies that timeout values can be configured via environment
func TestTimeoutConfigurationFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		getter   func(*Config) time.Duration
		expected time.Duration
	}{
		{
			name:     "DB_INIT_TIMEOUT",
			envKey:   "DB_INIT_TIMEOUT",
			envValue: "60s",
			getter:   func(c *Config) time.Duration { return c.DBInitTimeout },
			expected: 60 * time.Second,
		},
		{
			name:     "REDIS_CONN_TIMEOUT",
			envKey:   "REDIS_CONN_TIMEOUT",
			envValue: "10s",
			getter:   func(c *Config) time.Duration { return c.RedisConnTimeout },
			expected: 10 * time.Second,
		},
		{
			name:     "CACHE_INIT_TIMEOUT",
			envKey:   "CACHE_INIT_TIMEOUT",
			envValue: "3s",
			getter:   func(c *Config) time.Duration { return c.CacheInitTimeout },
			expected: 3 * time.Second,
		},
		{
			name:     "SERVER_SHUTDOWN_TIMEOUT",
			envKey:   "SERVER_SHUTDOWN_TIMEOUT",
			envValue: "30s",
			getter:   func(c *Config) time.Duration { return c.ServerShutdownTimeout },
			expected: 30 * time.Second,
		},
		{
			name:     "AUDIT_SHUTDOWN_TIMEOUT",
			envKey:   "AUDIT_SHUTDOWN_TIMEOUT",
			envValue: "15s",
			getter:   func(c *Config) time.Duration { return c.AuditShutdownTimeout },
			expected: 15 * time.Second,
		},
		{
			name:     "REDIS_CLOSE_TIMEOUT",
			envKey:   "REDIS_CLOSE_TIMEOUT",
			envValue: "3s",
			getter:   func(c *Config) time.Duration { return c.RedisCloseTimeout },
			expected: 3 * time.Second,
		},
		{
			name:     "CACHE_CLOSE_TIMEOUT",
			envKey:   "CACHE_CLOSE_TIMEOUT",
			envValue: "2s",
			getter:   func(c *Config) time.Duration { return c.CacheCloseTimeout },
			expected: 2 * time.Second,
		},
		{
			name:     "DB_CLOSE_TIMEOUT",
			envKey:   "DB_CLOSE_TIMEOUT",
			envValue: "8s",
			getter:   func(c *Config) time.Duration { return c.DBCloseTimeout },
			expected: 8 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable (automatically scoped to test)
			t.Setenv(tt.envKey, tt.envValue)

			// Load configuration
			cfg := Load()

			// Verify the value
			actual := tt.getter(cfg)
			assert.Equal(t, tt.expected, actual, "%s should be configurable via env", tt.envKey)
		})
	}
}

// TestTimeoutConfigurationInvalidValues verifies that invalid timeout values fall back to defaults
func TestTimeoutConfigurationInvalidValues(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		getter   func(*Config) time.Duration
		expected time.Duration
	}{
		{
			name:     "DB_INIT_TIMEOUT invalid",
			envKey:   "DB_INIT_TIMEOUT",
			envValue: "invalid",
			getter:   func(c *Config) time.Duration { return c.DBInitTimeout },
			expected: 30 * time.Second, // Should use default
		},
		{
			name:     "CACHE_INIT_TIMEOUT empty",
			envKey:   "CACHE_INIT_TIMEOUT",
			envValue: "",
			getter:   func(c *Config) time.Duration { return c.CacheInitTimeout },
			expected: 5 * time.Second, // Should use default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable (automatically scoped to test)
			t.Setenv(tt.envKey, tt.envValue)

			// Load configuration
			cfg := Load()

			// Verify the value falls back to default
			actual := tt.getter(cfg)
			assert.Equal(
				t,
				tt.expected,
				actual,
				"%s should fall back to default on invalid value",
				tt.envKey,
			)
		})
	}
}

// TestTimeoutReasonableValues verifies that timeout values are within reasonable ranges
func TestTimeoutReasonableValues(t *testing.T) {
	cfg := Load()

	// All timeouts should be positive
	assert.Positive(t, cfg.DBInitTimeout, "DB init timeout must be positive")
	assert.Positive(t, cfg.RedisConnTimeout, "Redis connection timeout must be positive")
	assert.Positive(t, cfg.CacheInitTimeout, "Cache init timeout must be positive")
	assert.Positive(t, cfg.ServerShutdownTimeout, "Server shutdown timeout must be positive")
	assert.Positive(t, cfg.AuditShutdownTimeout, "Audit shutdown timeout must be positive")
	assert.Positive(t, cfg.RedisCloseTimeout, "Redis close timeout must be positive")
	assert.Positive(t, cfg.CacheCloseTimeout, "Cache close timeout must be positive")
	assert.Positive(t, cfg.DBCloseTimeout, "DB close timeout must be positive")

	// Timeouts should be reasonable (not too short or too long)
	maxReasonableTimeout := 5 * time.Minute

	assert.LessOrEqual(
		t,
		cfg.DBInitTimeout,
		maxReasonableTimeout,
		"DB init timeout should be reasonable",
	)
	assert.LessOrEqual(
		t,
		cfg.RedisConnTimeout,
		maxReasonableTimeout,
		"Redis connection timeout should be reasonable",
	)
	assert.LessOrEqual(
		t,
		cfg.CacheInitTimeout,
		maxReasonableTimeout,
		"Cache init timeout should be reasonable",
	)
	assert.LessOrEqual(
		t,
		cfg.ServerShutdownTimeout,
		maxReasonableTimeout,
		"Server shutdown timeout should be reasonable",
	)
	assert.LessOrEqual(
		t,
		cfg.AuditShutdownTimeout,
		maxReasonableTimeout,
		"Audit shutdown timeout should be reasonable",
	)
	assert.LessOrEqual(
		t,
		cfg.RedisCloseTimeout,
		maxReasonableTimeout,
		"Redis close timeout should be reasonable",
	)
	assert.LessOrEqual(
		t,
		cfg.CacheCloseTimeout,
		maxReasonableTimeout,
		"Cache close timeout should be reasonable",
	)
	assert.LessOrEqual(
		t,
		cfg.DBCloseTimeout,
		maxReasonableTimeout,
		"DB close timeout should be reasonable",
	)

	// Minimum reasonable timeout (1 second)
	minReasonableTimeout := 1 * time.Second

	assert.GreaterOrEqual(
		t,
		cfg.DBInitTimeout,
		minReasonableTimeout,
		"DB init timeout should be at least 1s",
	)
	assert.GreaterOrEqual(
		t,
		cfg.RedisConnTimeout,
		minReasonableTimeout,
		"Redis connection timeout should be at least 1s",
	)
	assert.GreaterOrEqual(
		t,
		cfg.CacheInitTimeout,
		minReasonableTimeout,
		"Cache init timeout should be at least 1s",
	)
	assert.GreaterOrEqual(
		t,
		cfg.ServerShutdownTimeout,
		minReasonableTimeout,
		"Server shutdown timeout should be at least 1s",
	)
	assert.GreaterOrEqual(
		t,
		cfg.AuditShutdownTimeout,
		minReasonableTimeout,
		"Audit shutdown timeout should be at least 1s",
	)
	assert.GreaterOrEqual(
		t,
		cfg.RedisCloseTimeout,
		minReasonableTimeout,
		"Redis close timeout should be at least 1s",
	)
	assert.GreaterOrEqual(
		t,
		cfg.CacheCloseTimeout,
		minReasonableTimeout,
		"Cache close timeout should be at least 1s",
	)
	assert.GreaterOrEqual(
		t,
		cfg.DBCloseTimeout,
		minReasonableTimeout,
		"DB close timeout should be at least 1s",
	)
}
