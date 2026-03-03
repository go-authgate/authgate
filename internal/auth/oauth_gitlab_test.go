package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGitLabProvider_DefaultURL(t *testing.T) {
	p := NewGitLabProvider(OAuthProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"read_user"},
	}, "")

	assert.Equal(t, "gitlab", p.GetProvider())
	assert.Equal(t, "GitLab", p.GetDisplayName())
	assert.Equal(t, "https://gitlab.com/oauth/authorize", p.config.Endpoint.AuthURL)
	assert.Equal(t, "https://gitlab.com/oauth/token", p.config.Endpoint.TokenURL)
	assert.Equal(t, "https://gitlab.com/api/v4/user", p.apiURL)
}

func TestNewGitLabProvider_CustomURL(t *testing.T) {
	p := NewGitLabProvider(OAuthProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}, "https://gitlab.example.com")

	assert.Equal(t, "https://gitlab.example.com/oauth/authorize", p.config.Endpoint.AuthURL)
	assert.Equal(t, "https://gitlab.example.com/oauth/token", p.config.Endpoint.TokenURL)
	assert.Equal(t, "https://gitlab.example.com/api/v4/user", p.apiURL)
}

func TestNewGitLabProvider_TrailingSlashStripped(t *testing.T) {
	p := NewGitLabProvider(OAuthProviderConfig{}, "https://gitlab.example.com/")

	assert.Equal(t, "https://gitlab.example.com/oauth/authorize", p.config.Endpoint.AuthURL)
	assert.Equal(t, "https://gitlab.example.com/oauth/token", p.config.Endpoint.TokenURL)
	assert.Equal(t, "https://gitlab.example.com/api/v4/user", p.apiURL)
}

func TestGetGitLabUserInfo_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/user", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gitlabUser{
			ID:        42,
			Username:  "jdoe",
			Name:      "Jane Doe",
			Email:     "jane@example.com",
			AvatarURL: "https://gitlab.com/uploads/avatar.png",
		})
	}))
	defer server.Close()

	p := NewGitLabProvider(OAuthProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
	}, server.URL)

	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "42", info.ProviderUserID)
	assert.Equal(t, "jdoe", info.Username)
	assert.Equal(t, "Jane Doe", info.FullName)
	assert.Equal(t, "jane@example.com", info.Email)
	assert.Equal(t, "https://gitlab.com/uploads/avatar.png", info.AvatarURL)
}

func TestGetGitLabUserInfo_NoEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gitlabUser{
			ID:       1,
			Username: "noemail",
			Name:     "No Email",
			Email:    "", // empty
		})
	}))
	defer server.Close()

	p := NewGitLabProvider(OAuthProviderConfig{}, server.URL)
	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "no email address")
}

func TestGetGitLabUserInfo_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	}))
	defer server.Close()

	p := NewGitLabProvider(OAuthProviderConfig{}, server.URL)
	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "failed to get GitLab user info")
}

func TestGetGitLabUserInfo_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	p := NewGitLabProvider(OAuthProviderConfig{}, server.URL)
	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
}
