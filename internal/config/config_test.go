package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
			},
			expectError: false,
		},
		{
			name: "valid redis store",
			config: &Config{
				RateLimitStore:   RateLimitStoreRedis,
				MetricsCacheType: MetricsCacheTypeMemory,
			},
			expectError: false,
		},
		{
			name: "invalid store - typo",
			config: &Config{
				RateLimitStore:   "reddis",
				MetricsCacheType: MetricsCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "reddis"`,
		},
		{
			name: "invalid store - memcache",
			config: &Config{
				RateLimitStore:   "memcache",
				MetricsCacheType: MetricsCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "memcache"`,
		},
		{
			name: "invalid store - empty string",
			config: &Config{
				RateLimitStore:   "",
				MetricsCacheType: MetricsCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: ""`,
		},
		{
			name: "invalid store - uppercase",
			config: &Config{
				RateLimitStore:   "MEMORY",
				MetricsCacheType: MetricsCacheTypeMemory,
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "MEMORY"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
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
			},
			expectError: false,
		},
		{
			name: "valid redis cache with redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeRedis,
				RedisAddr:        "localhost:6379",
			},
			expectError: false,
		},
		{
			name: "valid redis-aside cache with redis address",
			config: &Config{
				RateLimitStore:   RateLimitStoreMemory,
				MetricsCacheType: MetricsCacheTypeRedisAside,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetricsCacheConstants(t *testing.T) {
	// Ensure constants are defined correctly
	assert.Equal(t, "memory", MetricsCacheTypeMemory)
	assert.Equal(t, "redis", MetricsCacheTypeRedis)
	assert.Equal(t, "redis-aside", MetricsCacheTypeRedisAside)
}
