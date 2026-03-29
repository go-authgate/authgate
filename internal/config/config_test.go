package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validBaseConfig returns a Config that passes all Validate() checks.
// Tests override specific fields to trigger the validation they want to test.
func validBaseConfig() Config {
	return Config{
		JWTExpiration:        time.Hour,
		RateLimitStore:       RateLimitStoreMemory,
		MetricsCacheType:     CacheTypeMemory,
		UserCacheType:        CacheTypeMemory,
		UserCacheTTL:         5 * time.Minute,
		ClientCountCacheType: CacheTypeMemory,
		ClientCountCacheTTL:  time.Minute,
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid memory store",
			modify:      func(_ *Config) {},
			expectError: false,
		},
		{
			name: "valid redis store",
			modify: func(c *Config) {
				c.RateLimitStore = RateLimitStoreRedis
			},
			expectError: false,
		},
		{
			name: "invalid store - typo",
			modify: func(c *Config) {
				c.RateLimitStore = "reddis"
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "reddis"`,
		},
		{
			name: "invalid store - memcache",
			modify: func(c *Config) {
				c.RateLimitStore = "memcache"
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "memcache"`,
		},
		{
			name: "invalid store - empty string",
			modify: func(c *Config) {
				c.RateLimitStore = ""
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: ""`,
		},
		{
			name: "invalid store - uppercase",
			modify: func(c *Config) {
				c.RateLimitStore = "MEMORY"
			},
			expectError: true,
			errorMsg:    `invalid RATE_LIMIT_STORE value: "MEMORY"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.modify(&cfg)
			err := cfg.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_Validate_JWTSigningAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		keyPath     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "HS256 default - no key required",
			algorithm:   "HS256",
			expectError: false,
		},
		{
			name:        "empty algorithm treated as HS256",
			algorithm:   "",
			expectError: false,
		},
		{
			name:        "RS256 requires key path",
			algorithm:   "RS256",
			expectError: true,
			errorMsg:    "JWT_PRIVATE_KEY_PATH is required",
		},
		{
			name:        "RS256 with key path OK",
			algorithm:   "RS256",
			keyPath:     "/some/key.pem",
			expectError: false,
		},
		{
			name:        "ES256 requires key path",
			algorithm:   "ES256",
			expectError: true,
			errorMsg:    "JWT_PRIVATE_KEY_PATH is required",
		},
		{
			name:        "ES256 with key path OK",
			algorithm:   "ES256",
			keyPath:     "/some/key.pem",
			expectError: false,
		},
		{
			name:        "unsupported algorithm",
			algorithm:   "PS256",
			expectError: true,
			errorMsg:    `invalid JWT_SIGNING_ALGORITHM value: "PS256"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.JWTSigningAlgorithm = tt.algorithm
			cfg.JWTPrivateKeyPath = tt.keyPath
			err := cfg.Validate()
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
		modify      func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid memory cache",
			modify:      func(_ *Config) {},
			expectError: false,
		},
		{
			name: "valid redis cache with redis address",
			modify: func(c *Config) {
				c.MetricsCacheType = CacheTypeRedis
				c.RedisAddr = "localhost:6379"
			},
			expectError: false,
		},
		{
			name: "valid redis-aside cache with redis address",
			modify: func(c *Config) {
				c.MetricsCacheType = CacheTypeRedisAside
				c.RedisAddr = "localhost:6379"
			},
			expectError: false,
		},
		{
			name: "invalid cache type - typo",
			modify: func(c *Config) {
				c.MetricsCacheType = "reddis"
			},
			expectError: true,
			errorMsg:    `invalid METRICS_CACHE_TYPE value: "reddis"`,
		},
		{
			name: "invalid cache type - memcached",
			modify: func(c *Config) {
				c.MetricsCacheType = "memcached"
			},
			expectError: true,
			errorMsg:    `invalid METRICS_CACHE_TYPE value: "memcached"`,
		},
		{
			name: "redis-aside without redis address",
			modify: func(c *Config) {
				c.MetricsCacheType = CacheTypeRedisAside
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `METRICS_CACHE_TYPE="redis-aside" requires REDIS_ADDR`,
		},
		{
			name: "redis cache type without redis address",
			modify: func(c *Config) {
				c.MetricsCacheType = CacheTypeRedis
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `METRICS_CACHE_TYPE="redis" requires REDIS_ADDR`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.modify(&cfg)
			err := cfg.Validate()

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
		modify      func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid memory user cache",
			modify:      func(_ *Config) {},
			expectError: false,
		},
		{
			name: "valid redis user cache with redis address",
			modify: func(c *Config) {
				c.UserCacheType = CacheTypeRedis
				c.RedisAddr = "localhost:6379"
			},
			expectError: false,
		},
		{
			name: "valid redis-aside user cache with redis address",
			modify: func(c *Config) {
				c.UserCacheType = CacheTypeRedisAside
				c.UserCacheClientTTL = 30 * time.Second
				c.RedisAddr = "localhost:6379"
			},
			expectError: false,
		},
		{
			name: "invalid user cache type",
			modify: func(c *Config) {
				c.UserCacheType = "invalid"
			},
			expectError: true,
			errorMsg:    `invalid USER_CACHE_TYPE value: "invalid"`,
		},
		{
			name: "redis user cache without redis address",
			modify: func(c *Config) {
				c.UserCacheType = CacheTypeRedis
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `USER_CACHE_TYPE="redis" requires REDIS_ADDR`,
		},
		{
			name: "redis-aside user cache without redis address",
			modify: func(c *Config) {
				c.UserCacheType = CacheTypeRedisAside
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `USER_CACHE_TYPE="redis-aside" requires REDIS_ADDR`,
		},
		{
			name: "zero UserCacheTTL rejected",
			modify: func(c *Config) {
				c.UserCacheTTL = 0
			},
			expectError: true,
			errorMsg:    "USER_CACHE_TTL must be a positive duration",
		},
		{
			name: "negative UserCacheTTL rejected",
			modify: func(c *Config) {
				c.UserCacheTTL = -1 * time.Second
			},
			expectError: true,
			errorMsg:    "USER_CACHE_TTL must be a positive duration",
		},
		{
			name: "zero UserCacheClientTTL rejected for redis-aside",
			modify: func(c *Config) {
				c.UserCacheType = CacheTypeRedisAside
				c.UserCacheClientTTL = 0
				c.RedisAddr = "localhost:6379"
			},
			expectError: true,
			errorMsg:    "USER_CACHE_CLIENT_TTL must be a positive duration",
		},
		{
			name: "zero UserCacheClientTTL allowed for non-redis-aside",
			modify: func(c *Config) {
				c.UserCacheClientTTL = 0 // irrelevant for memory backend
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.modify(&cfg)
			err := cfg.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCacheTypeConstants(t *testing.T) {
	assert.Equal(t, "memory", CacheTypeMemory)
	assert.Equal(t, "redis", CacheTypeRedis)
	assert.Equal(t, "redis-aside", CacheTypeRedisAside)
}

func TestClientCountCacheValidation(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid memory",
			modify:      func(_ *Config) {},
			expectError: false,
		},
		{
			name: "valid redis with redis address",
			modify: func(c *Config) {
				c.ClientCountCacheType = CacheTypeRedis
				c.RedisAddr = "localhost:6379"
			},
			expectError: false,
		},
		{
			name: "valid redis-aside with redis address",
			modify: func(c *Config) {
				c.ClientCountCacheType = CacheTypeRedisAside
				c.RedisAddr = "localhost:6379"
			},
			expectError: false,
		},
		{
			name: "invalid cache type",
			modify: func(c *Config) {
				c.ClientCountCacheType = "memcached"
			},
			expectError: true,
			errorMsg:    `invalid CLIENT_COUNT_CACHE_TYPE value: "memcached"`,
		},
		{
			name: "redis without redis address",
			modify: func(c *Config) {
				c.ClientCountCacheType = CacheTypeRedis
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `CLIENT_COUNT_CACHE_TYPE="redis" requires REDIS_ADDR`,
		},
		{
			name: "redis-aside without redis address",
			modify: func(c *Config) {
				c.ClientCountCacheType = CacheTypeRedisAside
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `CLIENT_COUNT_CACHE_TYPE="redis-aside" requires REDIS_ADDR`,
		},
		{
			name: "zero TTL",
			modify: func(c *Config) {
				c.ClientCountCacheTTL = -1
			},
			expectError: true,
			errorMsg:    "CLIENT_COUNT_CACHE_TTL must be a positive duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.modify(&cfg)
			err := cfg.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ============================================================
// JWT Expiration config
// ============================================================

func TestConfig_Validate_JWTExpiration(t *testing.T) {
	tests := []struct {
		name        string
		expiration  time.Duration
		expectError bool
		errorMsg    string
	}{
		{
			name:        "default 1 hour",
			expiration:  time.Hour,
			expectError: false,
		},
		{
			name:        "short 5 minutes",
			expiration:  5 * time.Minute,
			expectError: false,
		},
		{
			name:        "zero rejected",
			expiration:  0,
			expectError: true,
			errorMsg:    "JWT_EXPIRATION must be a positive duration",
		},
		{
			name:        "negative rejected",
			expiration:  -1 * time.Minute,
			expectError: true,
			errorMsg:    "JWT_EXPIRATION must be a positive duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.JWTExpiration = tt.expiration
			err := cfg.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestJWTExpirationEnvVar(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected time.Duration
	}{
		{
			name:     "custom value from env",
			envValue: "5m",
			expected: 5 * time.Minute,
		},
		{
			name:     "default without env var",
			envValue: "",
			expected: 10 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("JWT_EXPIRATION", tt.envValue)
			}
			cfg := Load()
			assert.Equal(t, tt.expected, cfg.JWTExpiration)
		})
	}
}

func TestConfig_Validate_JWTExpirationJitter(t *testing.T) {
	tests := []struct {
		name        string
		expiry      time.Duration
		jitter      time.Duration
		expectError bool
		errorMsg    string
	}{
		{
			name:        "disabled (default zero)",
			expiry:      time.Hour,
			jitter:      0,
			expectError: false,
		},
		{
			name:        "valid jitter less than expiry",
			expiry:      5 * time.Minute,
			jitter:      time.Minute,
			expectError: false,
		},
		{
			name:        "negative jitter rejected",
			expiry:      time.Hour,
			jitter:      -1 * time.Second,
			expectError: true,
			errorMsg:    "JWT_EXPIRATION_JITTER must be non-negative",
		},
		{
			name:        "jitter equal to expiry rejected",
			expiry:      5 * time.Minute,
			jitter:      5 * time.Minute,
			expectError: true,
			errorMsg:    "JWT_EXPIRATION_JITTER must be less than JWT_EXPIRATION",
		},
		{
			name:        "jitter greater than expiry rejected",
			expiry:      5 * time.Minute,
			jitter:      10 * time.Minute,
			expectError: true,
			errorMsg:    "JWT_EXPIRATION_JITTER must be less than JWT_EXPIRATION",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.JWTExpiration = tt.expiry
			cfg.JWTExpirationJitter = tt.jitter
			err := cfg.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
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
