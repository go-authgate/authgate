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
	SessionSecret string

	// Device code settings
	DeviceCodeExpiration time.Duration
	PollingInterval      int // seconds

	// Database
	DatabaseDriver string // "sqlite" or "postgres"
	DatabaseDSN    string // Database connection string (DSN or path)

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
		JWTSecret:            getEnv("JWT_SECRET", "your-256-bit-secret-change-in-production"),
		JWTExpiration:        time.Hour,
		SessionSecret:        getEnv("SESSION_SECRET", "session-secret-change-in-production"),
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		DatabaseDriver:       driver,
		DatabaseDSN:          dsn,

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
	for _, part := range strings.Split(s, sep) {
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

	return nil
}
