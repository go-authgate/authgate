package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid memory store",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: false,
		},
		{
			name: "valid redis store",
			config: &Config{
				RateLimitStore:   RateLimitStoreRedis,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: false,
		},
		{
			name: "invalid store - typo",
			config: &Config{
				RateLimitStore:   "reddis",
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "reddis"`,
		},
		{
			name: "invalid store - memcache",
			config: &Config{
				RateLimitStore:   "memcache",
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "memcache"`,
		},
		{
			name: "invalid store - empty string",
			config: &Config{
				RateLimitStore:   "",
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: ""`,
		},
		{
			name: "invalid store - uppercase",
			config: &Config{
				RateLimitStore:   "MEMORY",
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "MEMORY"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRateLimitStoreConstants(t *testing.T) {
	// Ensure constants are defined correctly
	assert.Equal(t, "memory", RateLimitStoreMemory)
	assert.Equal(t, "redis", RateLimitStoreRedis)
}

func TestMetricsCacheValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid memory cache",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: false,
		},
		{
			name: "valid redis cache with redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeRedis,
				UserCacheType:    UserCacheTypeMemory,
				RedisAddr:        "localhost:6379",
			},
			expectError: false,
		},
		{
			name: "valid redis-aside cache with redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeRedisAside,
				UserCacheType:    UserCacheTypeMemory,
				RedisAddr:        "localhost:6379",
			},
			expectError: false,
		},
		{
			name: "invalid cache type - typo",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: "reddis",
			},
			expectError: true,
			errorMsg:    `invalid METRICS_CACHE_TYPE value: "reddis"`,
		},
		{
			name: "invalid cache type - memcached",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: "memcached",
			},
			expectError: true,
			errorMsg:    `invalid METRICS_CACHE_TYPE value: "memcached"`,
		},
		{
			name: "redis-aside without redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeRedisAside,
				RedisAddr:        "",
			},
			expectError: true,
			errorMsg:    `METRICS_CACHE_TYPE="redis-aside" requires REDIS_ADDR`,
		},
		{
			name: "redis cache type without redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeRedis,
				RedisAddr:        "",
			},
			expectError: true,
			errorMsg:    `METRICS_CACHE_TYPE="redis" requires REDIS_ADDR`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUserCacheValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid memory user cache",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeMemory,
			},
			expectError: false,
		},
		{
			name: "valid redis user cache with redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeRedis,
				RedisAddr:        "localhost:6379",
			},
			expectError: false,
		},
		{
			name: "valid redis-aside user cache with redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeRedisAside,
				RedisAddr:        "localhost:6379",
			},
			expectError: false,
		},
		{
			name: "invalid user cache type",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    "invalid",
			},
			expectError: true,
			errorMsg:    `invalid USER_CACHE_TYPE value: "invalid"`,
		},
		{
			name: "redis user cache without redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeRedis,
				RedisAddr:        "",
			},
			expectError: true,
			errorMsg:    `USER_CACHE_TYPE="redis" requires REDIS_ADDR`,
		},
		{
			name: "redis-aside user cache without redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeMemory,
				UserCacheType:    UserCacheTypeRedisAside,
				RedisAddr:        "",
			},
			expectError: true,
			errorMsg:    `USER_CACHE_TYPE="redis-aside" requires REDIS_ADDR`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUserCacheConstants(t *testing.T) {
	assert.Equal(t, "memory", UserCacheTypeMemory)
	assert.Equal(t, "redis", UserCacheTypeRedis)
	assert.Equal(t, "redis-aside", UserCacheTypeRedisAside)
}

func TestMetricsCacheConstants(t *testing.T) {
	// Ensure constants are defined correctly
	assert.Equal(t, "memory", MetricsCacheTypeMemory)
	assert.Equal(t, "redis", MetricsCacheTypeRedis)
	assert.Equal(t, "redis-aside", MetricsCacheTypeRedisAside)
}

// ============================================================
// Authorization Code Flow config (RFC 6749 + RFC 7636)
// ============================================================

func TestAuthCodeFlowConfigDefaults(t *testing.T) {
	cfg := Load()

	assert.Equal(t, 10*time.Minute, cfg.AuthCodeExpiration)
	assert.False(t, cfg.PKCERequired)
	assert.True(t, cfg.ConsentRemember)
}

func TestAuthCodeFlowConfigFields(t *testing.T) {
	// Verify the fields exist and have sensible types/values
	cfg := &Config{
		AuthCodeExpiration: 5 * time.Minute,
		PKCERequired:       true,
		ConsentRemember:    false,
	}

	assert.Equal(t, 5*time.Minute, cfg.AuthCodeExpiration)
	assert.True(t, cfg.PKCERequired)
	assert.False(t, cfg.ConsentRemember)
}
