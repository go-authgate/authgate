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

func TestNewGiteaProvider(t *testing.T) {
	p := NewGiteaProvider(OAuthProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"read:user"},
	}, "https://gitea.example.com")

	assert.Equal(t, "gitea", p.GetProvider())
	assert.Equal(t, "Gitea", p.GetDisplayName())
	assert.Equal(t, "https://gitea.example.com/login/oauth/authorize", p.config.Endpoint.AuthURL)
	assert.Equal(
		t,
		"https://gitea.example.com/login/oauth/access_token",
		p.config.Endpoint.TokenURL,
	)
	assert.Equal(t, "https://gitea.example.com/api/v1/user", p.apiURL)
}

func TestNewGiteaProvider_TrailingSlashStripped(t *testing.T) {
	p := NewGiteaProvider(OAuthProviderConfig{}, "https://gitea.example.com/")

	assert.Equal(t, "https://gitea.example.com/login/oauth/authorize", p.config.Endpoint.AuthURL)
	assert.Equal(t, "https://gitea.example.com/api/v1/user", p.apiURL)
}

func TestGetGiteaUserInfo_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/user", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(giteaUser{
			ID:        99,
			Login:     "giteatester",
			FullName:  "Gitea Tester",
			Email:     "gitea@example.com",
			AvatarURL: "https://gitea.example.com/avatars/99",
		})
	}))
	defer server.Close()

	p := NewGiteaProvider(OAuthProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
	}, server.URL)

	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "99", info.ProviderUserID)
	assert.Equal(t, "giteatester", info.Username)
	assert.Equal(t, "Gitea Tester", info.FullName)
	assert.Equal(t, "gitea@example.com", info.Email)
	assert.Equal(t, "https://gitea.example.com/avatars/99", info.AvatarURL)
	assert.False(t, info.EmailVerified, "Gitea API does not expose email verification status")
}

func TestGetGiteaUserInfo_NoEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(giteaUser{ID: 1, Login: "noemail", Email: ""})
	}))
	defer server.Close()

	p := NewGiteaProvider(OAuthProviderConfig{}, server.URL)
	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "no email address")
}

func TestGetGiteaUserInfo_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer server.Close()

	p := NewGiteaProvider(OAuthProviderConfig{}, server.URL)
	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "failed to get Gitea user info")
}

func TestGetGiteaUserInfo_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	p := NewGiteaProvider(OAuthProviderConfig{}, server.URL)
	info, err := p.GetUserInfo(context.Background(), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
}
