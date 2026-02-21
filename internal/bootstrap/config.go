package bootstrap

import (
	"errors"
	"fmt"
	"log"

	"github.com/appleboy/authgate/internal/config"
)

// validateAllConfiguration validates all configuration settings
func validateAllConfiguration(cfg *config.Config) {
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	if err := validateAuthConfig(cfg); err != nil {
		log.Fatalf("Invalid authentication configuration: %v", err)
	}
	if err := validateTokenProviderConfig(cfg); err != nil {
		log.Fatalf("Invalid token provider configuration: %v", err)
	}
}

// validateAuthConfig checks that required config is present for selected auth mode
func validateAuthConfig(cfg *config.Config) error {
	switch cfg.AuthMode {
	case config.AuthModeHTTPAPI:
		if cfg.HTTPAPIURL == "" {
			return errors.New("HTTP_API_URL is required when AUTH_MODE=http_api")
		}
	case config.AuthModeLocal:
		// No additional validation needed
	default:
		return fmt.Errorf("invalid AUTH_MODE: %s (must be: local, http_api)", cfg.AuthMode)
	}
	return nil
}

// validateTokenProviderConfig checks that required config is present for selected token provider mode
func validateTokenProviderConfig(cfg *config.Config) error {
	switch cfg.TokenProviderMode {
	case config.TokenProviderModeHTTPAPI:
		if cfg.TokenAPIURL == "" {
			return errors.New("TOKEN_API_URL is required when TOKEN_PROVIDER_MODE=http_api")
		}
	case config.TokenProviderModeLocal:
		// No additional validation needed
	default:
		return fmt.Errorf(
			"invalid TOKEN_PROVIDER_MODE: %s (must be: local, http_api)",
			cfg.TokenProviderMode,
		)
	}
	return nil
}
