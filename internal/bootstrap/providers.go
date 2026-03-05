package bootstrap

import (
	"log"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/client"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/token"
)

// initializeHTTPAPIAuthProvider creates HTTP API auth provider when configured.
// Returns core.AuthProvider (not *auth.HTTPAPIAuthProvider) so that the nil
// default case is an untyped nil interface, keeping == nil checks in UserService safe.
func initializeHTTPAPIAuthProvider(cfg *config.Config) core.AuthProvider {
	switch cfg.AuthMode {
	case config.AuthModeHTTPAPI:
		authRetryClient, err := client.CreateRetryClient(client.RetryClientConfig{
			AuthMode:           cfg.HTTPAPIAuthMode,
			AuthSecret:         cfg.HTTPAPIAuthSecret,
			Timeout:            cfg.HTTPAPITimeout,
			InsecureSkipVerify: cfg.HTTPAPIInsecureSkipVerify,
			MaxRetries:         cfg.HTTPAPIMaxRetries,
			RetryDelay:         cfg.HTTPAPIRetryDelay,
			MaxRetryDelay:      cfg.HTTPAPIMaxRetryDelay,
			AuthHeader:         cfg.HTTPAPIAuthHeader,
		})
		if err != nil {
			log.Fatalf("Failed to create HTTP API auth client: %v", err)
		}
		log.Printf("HTTP API authentication enabled: %s", cfg.HTTPAPIURL)
		return auth.NewHTTPAPIAuthProvider(cfg, authRetryClient)
	default:
		return nil
	}
}

// initializeTokenProvider returns the configured TokenProvider.
// It always returns a concrete core.TokenProvider: an HTTP API provider when
// TokenProviderModeHTTPAPI is set, or a local token provider by default.
func initializeTokenProvider(cfg *config.Config) core.TokenProvider {
	switch cfg.TokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		tokenRetryClient, err := client.CreateRetryClient(client.RetryClientConfig{
			AuthMode:           cfg.TokenAPIAuthMode,
			AuthSecret:         cfg.TokenAPIAuthSecret,
			Timeout:            cfg.TokenAPITimeout,
			InsecureSkipVerify: cfg.TokenAPIInsecureSkipVerify,
			MaxRetries:         cfg.TokenAPIMaxRetries,
			RetryDelay:         cfg.TokenAPIRetryDelay,
			MaxRetryDelay:      cfg.TokenAPIMaxRetryDelay,
			AuthHeader:         cfg.TokenAPIAuthHeader,
		})
		if err != nil {
			log.Fatalf("Failed to create token API client: %v", err)
		}
		log.Printf("HTTP API token provider enabled: %s", cfg.TokenAPIURL)
		return token.NewHTTPTokenProvider(cfg, tokenRetryClient)
	default:
		return token.NewLocalTokenProvider(cfg)
	}
}
