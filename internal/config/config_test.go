package config

import (
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectPrefixCollision_Synthetic genuinely exercises the collision
// branch by passing a synthetic logical-name list directly to the helper.
// Pure-function call: no package-level state is mutated, so the test is
// safe under t.Parallel() and unaffected by other tests' Validate() calls.
//
// "time" is the synthetic addition: with prefix="auth", it composes to
// "auth_time" — already in staticReservedClaimKeys. The registry as
// shipped has no logical name that would collide for any plausible prefix,
// so the branch is otherwise unreachable.
func TestDetectPrefixCollision_Synthetic(t *testing.T) {
	logicalNames := append([]string{}, jwtPrivateClaimLogicalNames...)
	logicalNames = append(logicalNames, "time")
	err := detectPrefixCollision("auth", logicalNames, staticReservedClaimKeys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"auth_time"`,
		"error must name the colliding composed key")
	assert.Contains(t, err.Error(), "JWT_PRIVATE_CLAIM_PREFIX")
}

// TestDetectPrefixCollision_NoCollision pins the negative case alongside
// the positive one, so a future change to the helper that breaks the
// "no collision" path is caught.
func TestDetectPrefixCollision_NoCollision(t *testing.T) {
	err := detectPrefixCollision(
		"auth", jwtPrivateClaimLogicalNames, staticReservedClaimKeys,
	)
	assert.NoError(t, err,
		"prefix=auth must not collide with the as-shipped logical names")
}

// validBaseConfig returns a Config that passes all Validate() checks.
// Tests override specific fields to trigger the validation they want to test.
func validBaseConfig() Config {
	return Config{
		JWTSecret:             "test-secret-that-is-at-least-32b",
		JWTExpiration:         time.Hour,
		RateLimitStore:        RateLimitStoreMemory,
		MetricsCacheType:      CacheTypeMemory,
		UserCacheType:         CacheTypeMemory,
		UserCacheTTL:          5 * time.Minute,
		ClientCountCacheType:  CacheTypeMemory,
		ClientCountCacheTTL:   time.Minute,
		ClientCacheType:       CacheTypeMemory,
		ClientCacheTTL:        5 * time.Minute,
		JWTPrivateClaimPrefix: DefaultJWTPrivateClaimPrefix,
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
		keyPEM      string
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
			name:        "RS256 requires key path or PEM",
			algorithm:   "RS256",
			expectError: true,
			errorMsg:    "JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM is required",
		},
		{
			name:        "RS256 with key path OK",
			algorithm:   "RS256",
			keyPath:     "/some/key.pem",
			expectError: false,
		},
		{
			name:        "RS256 with inline PEM OK",
			algorithm:   "RS256",
			keyPEM:      "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
			expectError: false,
		},
		{
			name:        "RS256 with both path and PEM OK (PEM takes precedence at runtime)",
			algorithm:   "RS256",
			keyPath:     "/some/key.pem",
			keyPEM:      "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
			expectError: false,
		},
		{
			name:        "ES256 requires key path or PEM",
			algorithm:   "ES256",
			expectError: true,
			errorMsg:    "JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM is required",
		},
		{
			name:        "ES256 with key path OK",
			algorithm:   "ES256",
			keyPath:     "/some/key.pem",
			expectError: false,
		},
		{
			name:        "ES256 with inline PEM OK",
			algorithm:   "ES256",
			keyPEM:      "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n",
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
			cfg.JWTPrivateKeyPEM = tt.keyPEM
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
// Client Cache config
// ============================================================

func TestClientCacheValidation(t *testing.T) {
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
				c.ClientCacheType = CacheTypeRedis
				c.RedisAddr = "localhost:6379"
			},
			expectError: false,
		},
		{
			name: "valid redis-aside with redis address and client TTL",
			modify: func(c *Config) {
				c.ClientCacheType = CacheTypeRedisAside
				c.RedisAddr = "localhost:6379"
				c.ClientCacheClientTTL = 30 * time.Second
			},
			expectError: false,
		},
		{
			name: "invalid cache type",
			modify: func(c *Config) {
				c.ClientCacheType = "memcached"
			},
			expectError: true,
			errorMsg:    `invalid CLIENT_CACHE_TYPE value: "memcached"`,
		},
		{
			name: "redis without redis address",
			modify: func(c *Config) {
				c.ClientCacheType = CacheTypeRedis
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `CLIENT_CACHE_TYPE="redis" requires REDIS_ADDR`,
		},
		{
			name: "redis-aside without redis address",
			modify: func(c *Config) {
				c.ClientCacheType = CacheTypeRedisAside
				c.RedisAddr = ""
			},
			expectError: true,
			errorMsg:    `CLIENT_CACHE_TYPE="redis-aside" requires REDIS_ADDR`,
		},
		{
			name: "zero TTL",
			modify: func(c *Config) {
				c.ClientCacheTTL = -1
			},
			expectError: true,
			errorMsg:    "CLIENT_CACHE_TTL must be a positive duration",
		},
		{
			name: "redis-aside with zero client TTL",
			modify: func(c *Config) {
				c.ClientCacheType = CacheTypeRedisAside
				c.RedisAddr = "localhost:6379"
				c.ClientCacheClientTTL = 0
			},
			expectError: true,
			errorMsg:    `CLIENT_CACHE_CLIENT_TTL must be a positive duration when CLIENT_CACHE_TYPE="redis-aside"`,
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

func TestConfig_Validate_ExtraClaimsLimits(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "defaults are accepted",
			mutate:      func(*Config) {},
			expectError: false,
		},
		{
			name: "zero limits accepted (means disabled)",
			mutate: func(c *Config) {
				c.ExtraClaimsMaxRawSize = 0
				c.ExtraClaimsMaxKeys = 0
				c.ExtraClaimsMaxValSize = 0
			},
			expectError: false,
		},
		{
			name:        "negative max raw size rejected",
			mutate:      func(c *Config) { c.ExtraClaimsMaxRawSize = -1 },
			expectError: true,
			errorMsg:    "EXTRA_CLAIMS_MAX_RAW_SIZE must be non-negative",
		},
		{
			name:        "negative max keys rejected",
			mutate:      func(c *Config) { c.ExtraClaimsMaxKeys = -1 },
			expectError: true,
			errorMsg:    "EXTRA_CLAIMS_MAX_KEYS must be non-negative",
		},
		{
			name:        "negative max val size rejected",
			mutate:      func(c *Config) { c.ExtraClaimsMaxValSize = -1 },
			expectError: true,
			errorMsg:    "EXTRA_CLAIMS_MAX_VAL_SIZE must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.ExtraClaimsEnabled = true
			cfg.ExtraClaimsMaxRawSize = 4096
			cfg.ExtraClaimsMaxKeys = 16
			cfg.ExtraClaimsMaxValSize = 512
			tt.mutate(&cfg)
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

func TestConfig_Validate_JWTDomain(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		expectError bool
		errorMsg    string
	}{
		{name: "empty (feature off)", domain: "", expectError: false},
		{name: "single alnum", domain: "a", expectError: false},
		{name: "lowercase identifier", domain: "oa", expectError: false},
		{name: "with hyphen", domain: "swrd-prod", expectError: false},
		{name: "with underscore", domain: "my_domain", expectError: false},
		{name: "with dot", domain: "my.domain", expectError: false},
		{name: "uppercase preserved", domain: "OA", expectError: false},

		{
			name:        "contains spaces",
			domain:      "bad value with spaces",
			expectError: true,
			errorMsg:    `invalid JWT_DOMAIN value: "bad value with spaces"`,
		},
		{
			name:        "leading hyphen",
			domain:      "-foo",
			expectError: true,
			errorMsg:    `invalid JWT_DOMAIN value: "-foo"`,
		},
		{
			name:        "trailing hyphen",
			domain:      "foo-",
			expectError: true,
			errorMsg:    `invalid JWT_DOMAIN value: "foo-"`,
		},
		{
			name:        "contains slash",
			domain:      "foo/bar",
			expectError: true,
			errorMsg:    `invalid JWT_DOMAIN value: "foo/bar"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.JWTDomain = tt.domain
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

func TestLoad_JWTDomain(t *testing.T) {
	t.Run("default empty", func(t *testing.T) {
		cfg := Load()
		assert.Empty(t, cfg.JWTDomain)
	})

	t.Run("env value loaded", func(t *testing.T) {
		t.Setenv("JWT_DOMAIN", "oa")
		cfg := Load()
		assert.Equal(t, "oa", cfg.JWTDomain)
	})

	t.Run("env value trimmed", func(t *testing.T) {
		t.Setenv("JWT_DOMAIN", "  swrd  ")
		cfg := Load()
		assert.Equal(t, "swrd", cfg.JWTDomain)
	})
}

func TestLoad_SwaggerEnabled(t *testing.T) {
	t.Run("default false", func(t *testing.T) {
		cfg := Load()
		assert.False(t, cfg.SwaggerEnabled)
	})

	t.Run("env true", func(t *testing.T) {
		t.Setenv("ENABLE_SWAGGER", "true")
		cfg := Load()
		assert.True(t, cfg.SwaggerEnabled)
	})

	t.Run("env false", func(t *testing.T) {
		t.Setenv("ENABLE_SWAGGER", "false")
		cfg := Load()
		assert.False(t, cfg.SwaggerEnabled)
	})

	t.Run("decoupled from ENVIRONMENT", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("ENABLE_SWAGGER", "true")
		cfg := Load()
		assert.True(t, cfg.IsProduction)
		assert.True(t, cfg.SwaggerEnabled)
	})
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

func TestConfig_Validate_JWTSecretMinLength(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		algorithm   string
		expectError bool
	}{
		{
			name:        "HS256 with 32-byte secret passes",
			secret:      "test-secret-that-is-at-least-32b",
			algorithm:   "HS256",
			expectError: false,
		},
		{
			name:        "HS256 with short secret fails",
			secret:      "short",
			algorithm:   "HS256",
			expectError: true,
		},
		{
			name:        "empty algorithm (default HS256) with short secret fails",
			secret:      "short",
			algorithm:   "",
			expectError: true,
		},
		{
			name:        "RS256 with short secret is OK (uses key file, not secret)",
			secret:      "short",
			algorithm:   "RS256",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.JWTSecret = tt.secret
			cfg.JWTSigningAlgorithm = tt.algorithm
			if tt.algorithm == "RS256" || tt.algorithm == "ES256" {
				cfg.JWTPrivateKeyPath = "/tmp/fake.pem"
			}
			err := cfg.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "JWT_SECRET must be at least 32 bytes")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_Validate_SessionRememberMeMaxAge(t *testing.T) {
	t.Run("exceeds 30-day limit", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.SessionRememberMeEnabled = true
		cfg.SessionRememberMeMaxAge = 2592001
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds 30-day gorilla/sessions limit")
	})

	t.Run("exactly 30 days passes", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.SessionRememberMeEnabled = true
		cfg.SessionRememberMeMaxAge = 2592000
		err := cfg.Validate()
		require.NoError(t, err)
	})
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

func TestTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{"both empty", "", "", false},
		{"only cert set", "cert.pem", "", false},
		{"only key set", "", "key.pem", false},
		{"both set", "cert.pem", "key.pem", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{TLSCertFile: tt.certFile, TLSKeyFile: tt.keyFile}
			assert.Equal(t, tt.want, cfg.TLSEnabled())
		})
	}
}

func TestLoad_PopulatesTokenProfiles(t *testing.T) {
	// Load() reads from env vars; we want deterministic defaults in this test.
	t.Setenv("JWT_EXPIRATION", "2h")
	t.Setenv("REFRESH_TOKEN_EXPIRATION", "48h")

	cfg := Load()

	require.NotNil(t, cfg.TokenProfiles)
	short := cfg.TokenProfiles[models.TokenProfileShort]
	standard := cfg.TokenProfiles[models.TokenProfileStandard]
	long := cfg.TokenProfiles[models.TokenProfileLong]

	assert.Equal(t, 15*time.Minute, short.AccessTokenTTL)
	assert.Equal(t, 24*time.Hour, short.RefreshTokenTTL)
	// standard inherits the base JWT/refresh expirations
	assert.Equal(t, 2*time.Hour, standard.AccessTokenTTL)
	assert.Equal(t, 48*time.Hour, standard.RefreshTokenTTL)
	assert.Equal(t, 24*time.Hour, long.AccessTokenTTL)
	assert.Equal(t, 2160*time.Hour, long.RefreshTokenTTL)

	assert.Equal(t, 24*time.Hour, cfg.JWTExpirationMax)
	assert.Equal(t, 2160*time.Hour, cfg.RefreshTokenExpirationMax)
}

func TestLoad_TokenProfileEnvOverride(t *testing.T) {
	t.Setenv("TOKEN_PROFILE_SHORT_ACCESS_TTL", "5m")
	t.Setenv("TOKEN_PROFILE_LONG_REFRESH_TTL", "720h") // 30d

	cfg := Load()

	assert.Equal(t, 5*time.Minute, cfg.TokenProfiles[models.TokenProfileShort].AccessTokenTTL)
	assert.Equal(t, 720*time.Hour, cfg.TokenProfiles[models.TokenProfileLong].RefreshTokenTTL)
}

func TestValidate_TokenProfileExceedsMax(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*Config)
		expectedMsg string
	}{
		{
			name: "access TTL exceeds JWT_EXPIRATION_MAX",
			mutate: func(c *Config) {
				c.TokenProfiles[models.TokenProfileLong] = TokenProfile{
					AccessTokenTTL:  48 * time.Hour, // > cap
					RefreshTokenTTL: 24 * time.Hour,
				}
			},
			expectedMsg: "exceeds JWT_EXPIRATION_MAX",
		},
		{
			name: "refresh TTL exceeds REFRESH_TOKEN_EXPIRATION_MAX",
			mutate: func(c *Config) {
				c.TokenProfiles[models.TokenProfileLong] = TokenProfile{
					AccessTokenTTL:  time.Hour,
					RefreshTokenTTL: 5000 * time.Hour, // > cap
				}
			},
			expectedMsg: "exceeds REFRESH_TOKEN_EXPIRATION_MAX",
		},
		{
			name: "zero access TTL is rejected",
			mutate: func(c *Config) {
				c.TokenProfiles[models.TokenProfileShort] = TokenProfile{
					AccessTokenTTL:  0,
					RefreshTokenTTL: time.Hour,
				}
			},
			expectedMsg: `"short" access TTL must be a positive duration`,
		},
		{
			name: "missing profile is rejected",
			mutate: func(c *Config) {
				delete(c.TokenProfiles, models.TokenProfileLong)
			},
			expectedMsg: `token profile "long" is missing`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.JWTExpirationMax = 24 * time.Hour
			cfg.RefreshTokenExpirationMax = 2160 * time.Hour
			cfg.TokenProfiles = map[string]TokenProfile{
				models.TokenProfileShort: {
					AccessTokenTTL:  15 * time.Minute,
					RefreshTokenTTL: 24 * time.Hour,
				},
				models.TokenProfileStandard: {
					AccessTokenTTL:  time.Hour,
					RefreshTokenTTL: 720 * time.Hour,
				},
				models.TokenProfileLong: {
					AccessTokenTTL:  8 * time.Hour,
					RefreshTokenTTL: 2160 * time.Hour,
				},
			}
			tt.mutate(&cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedMsg)
		})
	}
}

func TestValidate_TokenProfileSkippedWhenZeroValue(t *testing.T) {
	// Hand-built test configs that don't care about token profiles must still pass
	// Validate() (used by many pre-existing tests).
	cfg := validBaseConfig()
	// TokenProfiles, JWTExpirationMax, RefreshTokenExpirationMax all zero
	require.NoError(t, cfg.Validate())
}

func TestValidate_TLSPartialConfig(t *testing.T) {
	tests := []struct {
		name      string
		certFile  string
		keyFile   string
		expectErr bool
	}{
		{"both empty passes", "", "", false},
		{"both set passes", "cert.pem", "key.pem", false},
		{"only cert set fails", "cert.pem", "", true},
		{"only key set fails", "", "key.pem", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.TLSCertFile = tt.certFile
			cfg.TLSKeyFile = tt.keyFile
			err := cfg.Validate()
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "TLS_CERT_FILE and TLS_KEY_FILE")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
