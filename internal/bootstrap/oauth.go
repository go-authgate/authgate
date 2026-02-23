package bootstrap

import (
	"log"
	"net/http"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/client"
	"github.com/go-authgate/authgate/internal/config"

	"github.com/appleboy/go-httpclient"
)

// initializeOAuthProviders initializes configured OAuth providers
func initializeOAuthProviders(cfg *config.Config) map[string]*auth.OAuthProvider {
	providers := make(map[string]*auth.OAuthProvider)

	// GitHub OAuth
	switch {
	case !cfg.GitHubOAuthEnabled:
		// Skip GitHub OAuth
	case cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "":
		log.Printf("Warning: GitHub OAuth enabled but CLIENT_ID or CLIENT_SECRET missing")
	default:
		providers["github"] = auth.NewGitHubProvider(auth.OAuthProviderConfig{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  cfg.GitHubOAuthRedirectURL,
			Scopes:       cfg.GitHubOAuthScopes,
		})
		log.Printf("GitHub OAuth configured: redirect=%s", cfg.GitHubOAuthRedirectURL)
	}

	// Gitea OAuth
	switch {
	case !cfg.GiteaOAuthEnabled:
		// Skip Gitea OAuth
	case cfg.GiteaURL == "" || cfg.GiteaClientID == "" || cfg.GiteaClientSecret == "":
		log.Printf("Warning: Gitea OAuth enabled but URL, CLIENT_ID or CLIENT_SECRET missing")
	default:
		providers["gitea"] = auth.NewGiteaProvider(auth.OAuthProviderConfig{
			ClientID:     cfg.GiteaClientID,
			ClientSecret: cfg.GiteaClientSecret,
			RedirectURL:  cfg.GiteaOAuthRedirectURL,
			Scopes:       cfg.GiteaOAuthScopes,
		}, cfg.GiteaURL)
		log.Printf(
			"Gitea OAuth configured: server=%s redirect=%s",
			cfg.GiteaURL,
			cfg.GiteaOAuthRedirectURL,
		)
	}

	// Microsoft Entra ID OAuth
	switch {
	case !cfg.MicrosoftOAuthEnabled:
		// Skip Microsoft OAuth
	case cfg.MicrosoftClientID == "" || cfg.MicrosoftClientSecret == "":
		log.Printf("Warning: Microsoft OAuth enabled but CLIENT_ID or CLIENT_SECRET missing")
	default:
		providers["microsoft"] = auth.NewMicrosoftProvider(auth.OAuthProviderConfig{
			ClientID:     cfg.MicrosoftClientID,
			ClientSecret: cfg.MicrosoftClientSecret,
			RedirectURL:  cfg.MicrosoftOAuthRedirectURL,
			Scopes:       cfg.MicrosoftOAuthScopes,
		}, cfg.MicrosoftTenantID)
		log.Printf(
			"Microsoft OAuth configured: tenant=%s redirect=%s",
			cfg.MicrosoftTenantID,
			cfg.MicrosoftOAuthRedirectURL,
		)
	}

	return providers
}

// getProviderNames returns a list of provider names
func getProviderNames(providers map[string]*auth.OAuthProvider) []string {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	return names
}

// createOAuthHTTPClient creates an HTTP client for OAuth requests with optimized connection pool
func createOAuthHTTPClient(cfg *config.Config) *http.Client {
	if cfg.OAuthInsecureSkipVerify {
		log.Printf("WARNING: OAuth TLS verification is disabled (OAUTH_INSECURE_SKIP_VERIFY=true)")
	}

	// Create optimized transport with connection pool settings
	transport := client.CreateOptimizedTransport(cfg.OAuthInsecureSkipVerify)

	httpClient, err := httpclient.NewClient(
		httpclient.WithTimeout(cfg.OAuthTimeout),
		httpclient.WithTransport(transport),
	)
	if err != nil {
		log.Fatalf("Failed to create OAuth HTTP client: %v", err)
	}

	return httpClient
}

// logOAuthProvidersStatus logs enabled OAuth providers
func logOAuthProvidersStatus(providers map[string]*auth.OAuthProvider) {
	if len(providers) > 0 {
		log.Printf("OAuth providers enabled: %v", getProviderNames(providers))
	}
}
