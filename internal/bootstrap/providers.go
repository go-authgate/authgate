package bootstrap

import (
	"log"

	"github.com/appleboy/authgate/internal/auth"
	"github.com/appleboy/authgate/internal/client"
	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/token"
)

// initializeHTTPAPIAuthProvider creates HTTP API auth provider when configured
func initializeHTTPAPIAuthProvider(cfg *config.Config) *auth.HTTPAPIAuthProvider {
	switch cfg.AuthMode {
	case config.AuthModeHTTPAPI:
		authRetryClient, err := client.CreateRetryClient(
			cfg.HTTPAPIAuthMode,
			cfg.HTTPAPIAuthSecret,
			cfg.HTTPAPITimeout,
			cfg.HTTPAPIInsecureSkipVerify,
			cfg.HTTPAPIMaxRetries,
			cfg.HTTPAPIRetryDelay,
			cfg.HTTPAPIMaxRetryDelay,
			cfg.HTTPAPIAuthHeader,
		)
		if err != nil {
			log.Fatalf("Failed to create HTTP API auth client: %v", err)
		}
		log.Printf("HTTP API authentication enabled: %s", cfg.HTTPAPIURL)
		return auth.NewHTTPAPIAuthProvider(cfg, authRetryClient)
	default:
		return nil
	}
}

// initializeHTTPTokenProvider creates HTTP token provider when configured
func initializeHTTPTokenProvider(cfg *config.Config) *token.HTTPTokenProvider {
	switch cfg.TokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		tokenRetryClient, err := client.CreateRetryClient(
			cfg.TokenAPIAuthMode,
			cfg.TokenAPIAuthSecret,
			cfg.TokenAPITimeout,
			cfg.TokenAPIInsecureSkipVerify,
			cfg.TokenAPIMaxRetries,
			cfg.TokenAPIRetryDelay,
			cfg.TokenAPIMaxRetryDelay,
			cfg.TokenAPIAuthHeader,
		)
		if err != nil {
			log.Fatalf("Failed to create token API client: %v", err)
		}
		log.Printf("HTTP API token provider enabled: %s", cfg.TokenAPIURL)
		return token.NewHTTPTokenProvider(cfg, tokenRetryClient)
	default:
		return nil
	}
}
