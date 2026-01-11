package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
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
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
