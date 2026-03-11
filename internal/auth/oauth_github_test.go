package auth

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGitHubProvider(t *testing.T) {
	p := NewGitHubProvider(OAuthProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"user:email"},
	})

	assert.Equal(t, "github", p.GetProvider())
	assert.Equal(t, "GitHub", p.GetDisplayName())
	assert.Equal(t, "https://github.com/login/oauth/authorize", p.config.Endpoint.AuthURL)
	assert.Equal(t, "https://github.com/login/oauth/access_token", p.config.Endpoint.TokenURL)
}

func TestGetGitHubUserInfo_Success(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(githubUser{
				ID:        12345,
				Login:     "octocat",
				Name:      "The Octocat",
				Email:     "octocat@github.com",
				AvatarURL: "https://github.com/avatars/octocat",
			})
			return
		}
		http.NotFound(w, r)
	})

	p := NewGitHubProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"})
	ctx := contextWithMock(handler)

	info, err := p.GetUserInfo(ctx, newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "12345", info.ProviderUserID)
	assert.Equal(t, "octocat", info.Username)
	assert.Equal(t, "The Octocat", info.FullName)
	assert.Equal(t, "octocat@github.com", info.Email)
	assert.Equal(t, "https://github.com/avatars/octocat", info.AvatarURL)
	assert.True(t, info.EmailVerified, "GitHub emails are always verified")
}

func TestGetGitHubUserInfo_FetchesPrimaryEmail(t *testing.T) {
	// Simulates a GitHub account with no public email: /user returns empty email,
	// so the provider falls back to /user/emails to find the primary verified address.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(githubUser{ID: 1, Login: "nomail", Email: ""})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]githubEmail{
				{Email: "secondary@example.com", Primary: false, Verified: true},
				{Email: "primary@example.com", Primary: true, Verified: true},
			})
		default:
			http.NotFound(w, r)
		}
	})

	p := NewGitHubProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "primary@example.com", info.Email)
	assert.True(t, info.EmailVerified)
}

func TestGetGitHubUserInfo_FallsBackToFirstVerifiedEmail(t *testing.T) {
	// No primary+verified email; provider should fall back to the first verified email.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(githubUser{ID: 1, Login: "user", Email: ""})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]githubEmail{
				{Email: "unverified@example.com", Primary: true, Verified: false},
				{Email: "fallback@example.com", Primary: false, Verified: true},
			})
		}
	})

	p := NewGitHubProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "fallback@example.com", info.Email)
}

func TestGetGitHubUserInfo_NoVerifiedEmail(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(githubUser{ID: 1, Login: "user", Email: ""})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]githubEmail{
				{Email: "unverified@example.com", Primary: true, Verified: false},
			})
		}
	})

	p := NewGitHubProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "no verified email")
}

func TestGetGitHubUserInfo_NonOKStatus(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	})

	p := NewGitHubProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "failed to get GitHub user info")
}

func TestGetGitHubUserInfo_InvalidJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	})

	p := NewGitHubProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
}
