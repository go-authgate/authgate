package config

import (
	"fmt"
	"os"
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

type Config struct {
	// Server settings
	ServerAddr string
	BaseURL    string

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
		ServerAddr:           getEnv("SERVER_ADDR", ":8080"),
		BaseURL:              getEnv("BASE_URL", "http://localhost:8080"),
		JWTSecret:            getEnv("JWT_SECRET", "your-256-bit-secret-change-in-production"),
		JWTExpiration:        time.Hour,
		SessionSecret:        getEnv("SESSION_SECRET", "session-secret-change-in-production"),
		DeviceCodeExpiration: 30 * time.Minute,
		PollingInterval:      5,
		DatabaseDriver:       driver,
		DatabaseDSN:          dsn,

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
