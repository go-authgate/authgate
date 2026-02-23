package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/microsoft"
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
	provider string // "github", "gitea", etc.
}

// NewGitHubProvider creates a new GitHub OAuth provider
func NewGitHubProvider(cfg OAuthProviderConfig) *OAuthProvider {
	return &OAuthProvider{
		provider: "github",
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
	return &OAuthProvider{
		provider: "gitea",
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
		provider: "microsoft",
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint:     microsoft.AzureADEndpoint(tenantID),
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
	case "github":
		return p.getGitHubUserInfo(ctx, token)
	case "gitea":
		return p.getGiteaUserInfo(ctx, token)
	case "microsoft":
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
	case "github":
		return "GitHub"
	case "gitea":
		return "Gitea"
	case "gitlab":
		return "GitLab"
	case "microsoft":
		return "Microsoft"
	default:
		// Capitalize first letter for unknown providers
		if len(p.provider) == 0 {
			return ""
		}
		// Convert first character to uppercase
		firstChar := p.provider[0]
		if firstChar >= 'a' && firstChar <= 'z' {
			firstChar -= 32
		}
		return string(firstChar) + p.provider[1:]
	}
}

// GitHub user info structures
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

// getGitHubUserInfo retrieves user info from GitHub API
func (p *OAuthProvider) getGitHubUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	// Get user profile
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(body))
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// If email is not public, fetch from emails endpoint
	if user.Email == "" {
		email, err := p.getGitHubPrimaryEmail(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("failed to get user email: %w", err)
		}
		user.Email = email
	}

	// GitHub requires email for our integration
	if user.Email == "" {
		return nil, errors.New("GitHub account has no email address")
	}

	return &OAuthUserInfo{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Username:       user.Login,
		Email:          user.Email,
		FullName:       user.Name,
		AvatarURL:      user.AvatarURL,
	}, nil
}

// getGitHubPrimaryEmail fetches primary email from GitHub emails endpoint
func (p *OAuthProvider) getGitHubPrimaryEmail(
	ctx context.Context,
	client *http.Client,
) (string, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "https://api.github.com/user/emails", nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get emails: %s", resp.Status)
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	// Find primary verified email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	// Fallback to first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", errors.New("no verified email found")
}

// Gitea user info structure
type giteaUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// getGiteaUserInfo retrieves user info from Gitea API
func (p *OAuthProvider) getGiteaUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	// Extract base URL from endpoint
	baseURL := p.config.Endpoint.AuthURL
	// Remove "/login/oauth/authorize" to get base URL
	apiURL := baseURL[:len(baseURL)-len("/login/oauth/authorize")] + "/api/v1/user"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gitea API error: %s - %s", resp.Status, string(body))
	}

	var user giteaUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Gitea requires email for our integration
	if user.Email == "" {
		return nil, errors.New("gitea account has no email address")
	}

	return &OAuthUserInfo{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Username:       user.Login,
		Email:          user.Email,
		FullName:       user.FullName,
		AvatarURL:      user.AvatarURL,
	}, nil
}

// Microsoft Graph API user info structure
type microsoftUser struct {
	ID                string `json:"id"`                // Object ID (UUID)
	UserPrincipalName string `json:"userPrincipalName"` // user@domain.com
	DisplayName       string `json:"displayName"`       // Full name
	Mail              string `json:"mail"`              // Email (may be empty)
	GivenName         string `json:"givenName"`         // First name
	Surname           string `json:"surname"`           // Last name
}

// getMicrosoftUserInfo retrieves user info from Microsoft Graph API
func (p *OAuthProvider) getMicrosoftUserInfo(
	ctx context.Context,
	token *oauth2.Token,
) (*OAuthUserInfo, error) {
	client := p.config.Client(ctx, token)

	// Call Microsoft Graph API v1.0
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "https://graph.microsoft.com/v1.0/me", nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("microsoft Graph API error: %s - %s", resp.Status, string(body))
	}

	var user microsoftUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Determine email: prefer mail, fallback to userPrincipalName
	email := user.Mail
	if email == "" {
		email = user.UserPrincipalName
	}

	// Email is required
	if email == "" {
		return nil, errors.New("microsoft account has no email address")
	}

	// Build full name
	fullName := user.DisplayName
	if fullName == "" && (user.GivenName != "" || user.Surname != "") {
		fullName = strings.TrimSpace(user.GivenName + " " + user.Surname)
	}

	// Extract username from email (part before @)
	username := strings.Split(email, "@")[0]

	return &OAuthUserInfo{
		ProviderUserID: user.ID,
		Username:       username,
		Email:          email,
		FullName:       fullName,
		AvatarURL:      "", // Microsoft Graph /me doesn't include photo by default
	}, nil
}
