package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/microsoft"
)

// Provider name constants
const (
	ProviderGitHub    = "github"
	ProviderGitea     = "gitea"
	ProviderGitLab    = "gitlab"
	ProviderMicrosoft = "microsoft"
)

// OAuthProviderConfig contains configuration for an OAuth provider
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// OAuthUserInfo contains user information from OAuth provider
type OAuthUserInfo struct {
	ProviderUserID string // Provider's user ID
	Username       string // Provider's username
	Email          string // User email (required)
	FullName       string // User full name
	AvatarURL      string // Avatar URL
}

// OAuthProvider handles OAuth authentication
type OAuthProvider struct {
	config   *oauth2.Config
	provider string // "github", "gitea", "gitlab", "microsoft", etc.
	apiURL   string // Pre-computed user info endpoint (set for instance-based providers)
}

// NewGitHubProvider creates a new GitHub OAuth provider
func NewGitHubProvider(cfg OAuthProviderConfig) *OAuthProvider {
	return &OAuthProvider{
		provider: ProviderGitHub,
		apiURL:   "https://api.github.com/user",
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     github.Endpoint,
		},
	}
}

// NewGiteaProvider creates a new Gitea OAuth provider
func NewGiteaProvider(cfg OAuthProviderConfig, giteaURL string) *OAuthProvider {
	giteaURL = strings.TrimSuffix(giteaURL, "/")
	return &OAuthProvider{
		provider: ProviderGitea,
		apiURL:   giteaURL + "/api/v1/user",
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  giteaURL + "/login/oauth/authorize",
				TokenURL: giteaURL + "/login/oauth/access_token",
			},
		},
	}
}

// NewMicrosoftProvider creates a new Microsoft Entra ID OAuth provider
func NewMicrosoftProvider(cfg OAuthProviderConfig, tenantID string) *OAuthProvider {
	return &OAuthProvider{
		provider: ProviderMicrosoft,
		apiURL:   "https://graph.microsoft.com/v1.0/me",
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     microsoft.AzureADEndpoint(tenantID),
		},
	}
}

// NewGitLabProvider creates a new GitLab OAuth provider.
// gitlabURL should be the base URL of the GitLab instance (e.g. "https://gitlab.com"
// or "https://gitlab.example.com" for self-hosted). It defaults to "https://gitlab.com"
// when empty.
func NewGitLabProvider(cfg OAuthProviderConfig, gitlabURL string) *OAuthProvider {
	if gitlabURL == "" {
		gitlabURL = "https://gitlab.com"
	}
	gitlabURL = strings.TrimSuffix(gitlabURL, "/")
	return &OAuthProvider{
		provider: ProviderGitLab,
		apiURL:   gitlabURL + "/api/v4/user",
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  gitlabURL + "/oauth/authorize",
				TokenURL: gitlabURL + "/oauth/token",
			},
		},
	}
}

// GetAuthURL returns the OAuth authorization URL
func (p *OAuthProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges authorization code for access token
func (p *OAuthProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

// GetUserInfo retrieves user information from the OAuth provider
func (p *OAuthProvider) GetUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	switch p.provider {
	case ProviderGitHub:
		return p.getGitHubUserInfo(ctx, token)
	case ProviderGitea:
		return p.getGiteaUserInfo(ctx, token)
	case ProviderGitLab:
		return p.getGitLabUserInfo(ctx, token)
	case ProviderMicrosoft:
		return p.getMicrosoftUserInfo(ctx, token)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", p.provider)
	}
}

// GetProvider returns the provider name
func (p *OAuthProvider) GetProvider() string {
	return p.provider
}

// GetDisplayName returns the human-readable provider name
func (p *OAuthProvider) GetDisplayName() string {
	switch p.provider {
	case ProviderGitHub:
		return "GitHub"
	case ProviderGitea:
		return "Gitea"
	case ProviderGitLab:
		return "GitLab"
	case ProviderMicrosoft:
		return "Microsoft"
	default:
		if len(p.provider) == 0 {
			return ""
		}
		return strings.ToUpper(p.provider[:1]) + p.provider[1:]
	}
}

// fetchJSON makes a GET request and decodes the JSON response body into dest.
func fetchJSON(ctx context.Context, client *http.Client, url string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("unexpected status %s (failed to read body: %w)", resp.Status, err)
		}
		return fmt.Errorf("unexpected status %s: %s", resp.Status, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}
