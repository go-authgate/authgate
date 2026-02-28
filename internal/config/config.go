package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Authentication mode constants
const (
	AuthModeLocal   = "local"
	AuthModeHTTPAPI = "http_api"
)

// Token provider mode constants
const (
	TokenProviderModeLocal   = "local"
	TokenProviderModeHTTPAPI = "http_api"
)

// Rate limit store constants
const (
	RateLimitStoreMemory = "memory"
	RateLimitStoreRedis  = "redis"
)

// Metrics cache type constants
const (
	MetricsCacheTypeMemory     = "memory"
	MetricsCacheTypeRedis      = "redis"
	MetricsCacheTypeRedisAside = "redis-aside"
)

// User cache type constants
const (
	UserCacheTypeMemory     = "memory"
	UserCacheTypeRedis      = "redis"
	UserCacheTypeRedisAside = "redis-aside"
)

type Config struct {
	// Server settings
	ServerAddr string
	BaseURL    string

	// Environment detection
	IsProduction bool

	// JWT settings
	JWTSecret     string
	JWTExpiration time.Duration

	// Session settings
	SessionSecret        string
	SessionMaxAge        int  // Session max age in seconds (default: 3600 = 1 hour)
	SessionIdleTimeout   int  // Session idle timeout in seconds (0 = disabled, default: 1800 = 30 minutes)
	SessionFingerprint   bool // Enable session fingerprinting (IP + User-Agent validation, default: true)
	SessionFingerprintIP bool // Include IP address in fingerprint (default: false, due to dynamic IPs)

	// Device code settings
	DeviceCodeExpiration time.Duration
	PollingInterval      int // seconds

	// Database
	DatabaseDriver string // "sqlite" or "postgres"
	DatabaseDSN    string // Database connection string (DSN or path)

	// Database connection pool settings
	DBMaxOpenConns    int           // Maximum number of open connections (default: 25)
	DBMaxIdleConns    int           // Maximum number of idle connections (default: 10)
	DBConnMaxLifetime time.Duration // Maximum connection lifetime (default: 5 minutes)
	DBConnMaxIdleTime time.Duration // Maximum connection idle time (default: 10 minutes)

	// Default Admin User
	DefaultAdminPassword string // Default admin password (if empty, random password is generated)

	// Authentication
	AuthMode string // "local" or "http_api"

	// HTTP API Authentication
	HTTPAPIURL                string
	HTTPAPITimeout            time.Duration
	HTTPAPIInsecureSkipVerify bool
	HTTPAPIAuthMode           string // Authentication mode: "none", "simple", or "hmac"
	HTTPAPIAuthSecret         string // Shared secret for authentication
	HTTPAPIAuthHeader         string // Custom header name for simple mode (default: "X-API-Secret")
	HTTPAPIMaxRetries         int    // Maximum retry attempts (default: 3)
	HTTPAPIRetryDelay         time.Duration
	HTTPAPIMaxRetryDelay      time.Duration

	// Token Provider
	TokenProviderMode string // "local" or "http_api"

	// HTTP API Token Provider
	TokenAPIURL                string
	TokenAPITimeout            time.Duration
	TokenAPIInsecureSkipVerify bool
	TokenAPIAuthMode           string // Authentication mode: "none", "simple", or "hmac"
	TokenAPIAuthSecret         string // Shared secret for authentication
	TokenAPIAuthHeader         string // Custom header name for simple mode (default: "X-API-Secret")
	TokenAPIMaxRetries         int    // Maximum retry attempts (default: 3)
	TokenAPIRetryDelay         time.Duration
	TokenAPIMaxRetryDelay      time.Duration

	// Refresh Token settings
	RefreshTokenExpiration time.Duration // Refresh token lifetime (default: 720h = 30 days)
	EnableRefreshTokens    bool          // Feature flag to enable/disable refresh tokens (default: true)
	EnableTokenRotation    bool          // Enable token rotation mode (default: false, fixed mode)

	// Client Credentials Flow settings (RFC 6749 §4.4)
	ClientCredentialsTokenExpiration time.Duration // Access token lifetime for client_credentials grant (default: 1h, same as JWTExpiration)

	// OAuth settings
	// GitHub OAuth
	GitHubOAuthEnabled     bool
	GitHubClientID         string
	GitHubClientSecret     string
	GitHubOAuthRedirectURL string
	GitHubOAuthScopes      []string

	// Gitea OAuth
	GiteaOAuthEnabled     bool
	GiteaURL              string
	GiteaClientID         string
	GiteaClientSecret     string
	GiteaOAuthRedirectURL string
	GiteaOAuthScopes      []string

	// Microsoft Entra ID OAuth
	MicrosoftOAuthEnabled     bool
	MicrosoftTenantID         string // "common", "organizations", or tenant UUID
	MicrosoftClientID         string
	MicrosoftClientSecret     string
	MicrosoftOAuthRedirectURL string
	MicrosoftOAuthScopes      []string

	// OAuth Auto Registration
	OAuthAutoRegister bool // Allow OAuth to auto-create accounts (default: true)

	// OAuth HTTP Client Settings
	OAuthTimeout            time.Duration // HTTP client timeout for OAuth requests (default: 15s)
	OAuthInsecureSkipVerify bool          // Skip TLS verification for OAuth (dev/testing only, default: false)

	// Rate Limiting settings
	EnableRateLimit          bool   // Enable rate limiting (default: true)
	RateLimitStore           string // Rate limit store: "memory" or "redis" (default: "memory")
	RateLimitCleanupInterval time.Duration
	LoginRateLimit           int // Requests per minute for /login endpoint (default: 5)
	DeviceCodeRateLimit      int // Requests per minute for /oauth/device/code (default: 10)
	TokenRateLimit           int // Requests per minute for /oauth/token (default: 20)
	DeviceVerifyRateLimit    int // Requests per minute for /device/verify (default: 10)

	// Redis settings (only used when RateLimitStore = "redis")
	RedisAddr     string // Redis address for rate limiting (e.g., "localhost:6379")
	RedisPassword string // Redis password (empty for no auth)
	RedisDB       int    // Redis database number (default: 0)

	// Audit Logging settings
	EnableAuditLogging      bool          // Enable audit logging (default: true)
	AuditLogRetention       time.Duration // Retention period for audit logs (default: 90 days)
	AuditLogBufferSize      int           // Async buffer size (default: 1000)
	AuditLogCleanupInterval time.Duration // Cleanup interval (default: 24 hours)

	// Prometheus Metrics settings
	MetricsEnabled             bool          // Enable Prometheus metrics endpoint (default: false)
	MetricsToken               string        // Bearer token for /metrics (empty = no auth, recommended for production)
	MetricsGaugeUpdateEnabled  bool          // Enable gauge metric updates (default: true, disable on all but one replica)
	MetricsGaugeUpdateInterval time.Duration // Gauge update interval (default: 5m)
	MetricsCacheType           string        // Cache backend: memory, redis, redis-aside (default: memory)
	MetricsCacheClientTTL      time.Duration // Client-side cache TTL for redis-aside (default: 30s)
	MetricsCacheSizePerConn    int           // Client-side cache size per connection in MB for redis-aside (default: 32MB)

	// User Cache settings
	UserCacheType      string        // USER_CACHE_TYPE: memory|redis|redis-aside (default: memory)
	UserCacheTTL       time.Duration // USER_CACHE_TTL (default: 5m)
	UserCacheClientTTL time.Duration // USER_CACHE_CLIENT_TTL for redis-aside client-side TTL (default: 30s)

	// Authorization Code Flow settings (RFC 6749)
	AuthCodeExpiration time.Duration // Authorization code lifetime (default: 10 minutes)
	PKCERequired       bool          // Force PKCE for all public clients (default: false)
	ConsentRemember    bool          // Skip consent page if user already authorized same scope (default: true)

	// Bootstrap and shutdown timeout settings
	DBInitTimeout         time.Duration // Database initialization timeout (default: 30s)
	RedisConnTimeout      time.Duration // Redis connection timeout (default: 5s)
	CacheInitTimeout      time.Duration // Cache initialization timeout (default: 5s)
	ServerShutdownTimeout time.Duration // HTTP server graceful shutdown timeout (default: 5s)
	AuditShutdownTimeout  time.Duration // Audit service shutdown timeout (default: 10s)
	RedisCloseTimeout     time.Duration // Redis close timeout (default: 5s)
	CacheCloseTimeout     time.Duration // Cache close timeout (default: 5s)
	DBCloseTimeout        time.Duration // Database close timeout (default: 5s)
}

func Load() *Config {
	// Load .env file if exists (ignore error if not found)
	_ = godotenv.Load()

	// Determine database driver and DSN
	driver := getEnv("DATABASE_DRIVER", "sqlite")
	var dsn string
	if driver == "sqlite" {
		dsn = getEnv("DATABASE_DSN", getEnv("DATABASE_PATH", "oauth.db"))
	} else {
		dsn = getEnv("DATABASE_DSN", "")
	}

	return &Config{
		ServerAddr: getEnv("SERVER_ADDR", ":8080"),
		BaseURL:    getEnv("BASE_URL", "http://localhost:8080"),
		IsProduction: getEnvBool("ENVIRONMENT", false) ||
			getEnv("ENVIRONMENT", "") == "production",
		JWTSecret:          getEnv("JWT_SECRET", "your-256-bit-secret-change-in-production"),
		JWTExpiration:      time.Hour,
		SessionSecret:      getEnv("SESSION_SECRET", "session-secret-change-in-production"),
		SessionMaxAge:      getEnvInt("SESSION_MAX_AGE", 3600),      // 1 hour default
		SessionIdleTimeout: getEnvInt("SESSION_IDLE_TIMEOUT", 1800), // 30 minutes default
		SessionFingerprint: getEnvBool("SESSION_FINGERPRINT", true), // Enabled by default
		SessionFingerprintIP: getEnvBool(
			"SESSION_FINGERPRINT_IP",
			false,
		), // Disabled by default (dynamic IPs)
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		DatabaseDriver:       driver,
		DatabaseDSN:          dsn,
		DBMaxOpenConns:       getEnvInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:       getEnvInt("DB_MAX_IDLE_CONNS", 10),
		DBConnMaxLifetime:    getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		DBConnMaxIdleTime:    getEnvDuration("DB_CONN_MAX_IDLE_TIME", 10*time.Minute),

		// Default Admin User
		DefaultAdminPassword: getEnv("DEFAULT_ADMIN_PASSWORD", ""),

		// Authentication
		AuthMode: getEnv("AUTH_MODE", AuthModeLocal),

		// HTTP API Authentication
		HTTPAPIURL:                getEnv("HTTP_API_URL", ""),
		HTTPAPITimeout:            getEnvDuration("HTTP_API_TIMEOUT", 10*time.Second),
		HTTPAPIInsecureSkipVerify: getEnvBool("HTTP_API_INSECURE_SKIP_VERIFY", false),
		HTTPAPIAuthMode:           getEnv("HTTP_API_AUTH_MODE", "none"),
		HTTPAPIAuthSecret:         getEnv("HTTP_API_AUTH_SECRET", ""),
		HTTPAPIAuthHeader:         getEnv("HTTP_API_AUTH_HEADER", "X-API-Secret"),
		HTTPAPIMaxRetries:         getEnvInt("HTTP_API_MAX_RETRIES", 3),
		HTTPAPIRetryDelay:         getEnvDuration("HTTP_API_RETRY_DELAY", 1*time.Second),
		HTTPAPIMaxRetryDelay:      getEnvDuration("HTTP_API_MAX_RETRY_DELAY", 10*time.Second),

		// Token Provider
		TokenProviderMode: getEnv("TOKEN_PROVIDER_MODE", TokenProviderModeLocal),

		// HTTP API Token Provider
		TokenAPIURL:                getEnv("TOKEN_API_URL", ""),
		TokenAPITimeout:            getEnvDuration("TOKEN_API_TIMEOUT", 10*time.Second),
		TokenAPIInsecureSkipVerify: getEnvBool("TOKEN_API_INSECURE_SKIP_VERIFY", false),
		TokenAPIAuthMode:           getEnv("TOKEN_API_AUTH_MODE", "none"),
		TokenAPIAuthSecret:         getEnv("TOKEN_API_AUTH_SECRET", ""),
		TokenAPIAuthHeader:         getEnv("TOKEN_API_AUTH_HEADER", "X-API-Secret"),
		TokenAPIMaxRetries:         getEnvInt("TOKEN_API_MAX_RETRIES", 3),
		TokenAPIRetryDelay:         getEnvDuration("TOKEN_API_RETRY_DELAY", 1*time.Second),
		TokenAPIMaxRetryDelay:      getEnvDuration("TOKEN_API_MAX_RETRY_DELAY", 10*time.Second),

		// Refresh Token settings
		RefreshTokenExpiration: getEnvDuration(
			"REFRESH_TOKEN_EXPIRATION",
			720*time.Hour,
		), // 30 days
		EnableRefreshTokens: getEnvBool("ENABLE_REFRESH_TOKENS", true),
		EnableTokenRotation: getEnvBool("ENABLE_TOKEN_ROTATION", false),

		// Client Credentials Flow settings
		ClientCredentialsTokenExpiration: getEnvDuration(
			"CLIENT_CREDENTIALS_TOKEN_EXPIRATION",
			time.Hour,
		), // 1 hour default; keep short — no refresh token means no rotation mechanism

		// OAuth settings
		// GitHub OAuth
		GitHubOAuthEnabled:     getEnvBool("GITHUB_OAUTH_ENABLED", false),
		GitHubClientID:         getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:     getEnv("GITHUB_CLIENT_SECRET", ""),
		GitHubOAuthRedirectURL: getEnv("GITHUB_REDIRECT_URL", ""),
		GitHubOAuthScopes:      getEnvSlice("GITHUB_SCOPES", []string{"user:email"}),

		// Gitea OAuth
		GiteaOAuthEnabled:     getEnvBool("GITEA_OAUTH_ENABLED", false),
		GiteaURL:              getEnv("GITEA_URL", ""),
		GiteaClientID:         getEnv("GITEA_CLIENT_ID", ""),
		GiteaClientSecret:     getEnv("GITEA_CLIENT_SECRET", ""),
		GiteaOAuthRedirectURL: getEnv("GITEA_REDIRECT_URL", ""),
		GiteaOAuthScopes:      getEnvSlice("GITEA_SCOPES", []string{"read:user"}),

		// Microsoft Entra ID OAuth
		MicrosoftOAuthEnabled:     getEnvBool("MICROSOFT_OAUTH_ENABLED", false),
		MicrosoftTenantID:         getEnv("MICROSOFT_TENANT_ID", "common"),
		MicrosoftClientID:         getEnv("MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret:     getEnv("MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftOAuthRedirectURL: getEnv("MICROSOFT_REDIRECT_URL", ""),
		MicrosoftOAuthScopes: getEnvSlice(
			"MICROSOFT_SCOPES",
			[]string{"openid", "profile", "email", "User.Read"},
		),

		// OAuth Auto Registration
		OAuthAutoRegister: getEnvBool("OAUTH_AUTO_REGISTER", true),

		// OAuth HTTP Client Settings
		OAuthTimeout:            getEnvDuration("OAUTH_TIMEOUT", 15*time.Second),
		OAuthInsecureSkipVerify: getEnvBool("OAUTH_INSECURE_SKIP_VERIFY", false),

		// Rate Limiting settings
		EnableRateLimit:          getEnvBool("ENABLE_RATE_LIMIT", true),
		RateLimitStore:           getEnv("RATE_LIMIT_STORE", "memory"),
		RateLimitCleanupInterval: getEnvDuration("RATE_LIMIT_CLEANUP_INTERVAL", 5*time.Minute),
		LoginRateLimit:           getEnvInt("LOGIN_RATE_LIMIT", 5),
		DeviceCodeRateLimit:      getEnvInt("DEVICE_CODE_RATE_LIMIT", 10),
		TokenRateLimit:           getEnvInt("TOKEN_RATE_LIMIT", 20),
		DeviceVerifyRateLimit:    getEnvInt("DEVICE_VERIFY_RATE_LIMIT", 10),

		// Redis settings
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvInt("REDIS_DB", 0),

		// Audit Logging settings
		EnableAuditLogging:      getEnvBool("ENABLE_AUDIT_LOGGING", true),
		AuditLogRetention:       getEnvDuration("AUDIT_LOG_RETENTION", 90*24*time.Hour), // 90 days
		AuditLogBufferSize:      getEnvInt("AUDIT_LOG_BUFFER_SIZE", 1000),
		AuditLogCleanupInterval: getEnvDuration("AUDIT_LOG_CLEANUP_INTERVAL", 24*time.Hour),

		// Prometheus Metrics settings
		MetricsEnabled:             getEnvBool("METRICS_ENABLED", false),
		MetricsToken:               getEnv("METRICS_TOKEN", ""),
		MetricsGaugeUpdateEnabled:  getEnvBool("METRICS_GAUGE_UPDATE_ENABLED", true),
		MetricsGaugeUpdateInterval: getEnvDuration("METRICS_GAUGE_UPDATE_INTERVAL", 5*time.Minute),
		MetricsCacheType:           getEnv("METRICS_CACHE_TYPE", MetricsCacheTypeMemory),
		MetricsCacheClientTTL:      getEnvDuration("METRICS_CACHE_CLIENT_TTL", 30*time.Second),
		MetricsCacheSizePerConn:    getEnvInt("METRICS_CACHE_SIZE_PER_CONN", 32), // 32MB default

		// User Cache settings
		UserCacheType:      getEnv("USER_CACHE_TYPE", UserCacheTypeMemory),
		UserCacheTTL:       getEnvDuration("USER_CACHE_TTL", 5*time.Minute),
		UserCacheClientTTL: getEnvDuration("USER_CACHE_CLIENT_TTL", 30*time.Second),

		// Authorization Code Flow settings
		AuthCodeExpiration: getEnvDuration("AUTH_CODE_EXPIRATION", 10*time.Minute),
		PKCERequired:       getEnvBool("PKCE_REQUIRED", false),
		ConsentRemember:    getEnvBool("CONSENT_REMEMBER", true),

		// Bootstrap and shutdown timeout settings
		DBInitTimeout:         getEnvDuration("DB_INIT_TIMEOUT", 30*time.Second),
		RedisConnTimeout:      getEnvDuration("REDIS_CONN_TIMEOUT", 5*time.Second),
		CacheInitTimeout:      getEnvDuration("CACHE_INIT_TIMEOUT", 5*time.Second),
		ServerShutdownTimeout: getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 5*time.Second),
		AuditShutdownTimeout:  getEnvDuration("AUDIT_SHUTDOWN_TIMEOUT", 10*time.Second),
		RedisCloseTimeout:     getEnvDuration("REDIS_CLOSE_TIMEOUT", 5*time.Second),
		CacheCloseTimeout:     getEnvDuration("CACHE_CLOSE_TIMEOUT", 5*time.Second),
		DBCloseTimeout:        getEnvDuration("DB_CLOSE_TIMEOUT", 5*time.Second),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var i int
		if _, err := fmt.Sscanf(value, "%d", &i); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Split by comma and trim spaces
		parts := []string{}
		for _, part := range splitAndTrim(value, ",") {
			if part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) > 0 {
			return parts
		}
	}
	return defaultValue
}

func splitAndTrim(s, sep string) []string {
	var out []string
	for part := range strings.SplitSeq(s, sep) {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Validate checks the configuration for invalid values
func (c *Config) Validate() error {
	// Validate rate limit store type
	if c.RateLimitStore != RateLimitStoreMemory && c.RateLimitStore != RateLimitStoreRedis {
		return fmt.Errorf(
			"invalid RATE_LIMIT_STORE value: %q (must be %q or %q)",
			c.RateLimitStore,
			RateLimitStoreMemory,
			RateLimitStoreRedis,
		)
	}

	// Validate metrics cache type
	if c.MetricsCacheType != MetricsCacheTypeMemory &&
		c.MetricsCacheType != MetricsCacheTypeRedis &&
		c.MetricsCacheType != MetricsCacheTypeRedisAside {
		return fmt.Errorf(
			"invalid METRICS_CACHE_TYPE value: %q (must be %q, %q, or %q)",
			c.MetricsCacheType,
			MetricsCacheTypeMemory,
			MetricsCacheTypeRedis,
			MetricsCacheTypeRedisAside,
		)
	}

	// Validate redis-based metrics cache types require Redis configuration
	if (c.MetricsCacheType == MetricsCacheTypeRedis || c.MetricsCacheType == MetricsCacheTypeRedisAside) &&
		c.RedisAddr == "" {
		return fmt.Errorf(
			"METRICS_CACHE_TYPE=%q requires REDIS_ADDR to be configured",
			c.MetricsCacheType,
		)
	}

	// Validate user cache type
	if c.UserCacheType != UserCacheTypeMemory &&
		c.UserCacheType != UserCacheTypeRedis &&
		c.UserCacheType != UserCacheTypeRedisAside {
		return fmt.Errorf(
			"invalid USER_CACHE_TYPE value: %q (must be %q, %q, or %q)",
			c.UserCacheType, UserCacheTypeMemory, UserCacheTypeRedis, UserCacheTypeRedisAside,
		)
	}

	// Redis-based user cache requires Redis configuration
	if (c.UserCacheType == UserCacheTypeRedis || c.UserCacheType == UserCacheTypeRedisAside) &&
		c.RedisAddr == "" {
		return fmt.Errorf(
			"USER_CACHE_TYPE=%q requires REDIS_ADDR to be configured",
			c.UserCacheType,
		)
	}

	return nil
}
