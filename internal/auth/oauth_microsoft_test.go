package auth

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMicrosoftProvider(t *testing.T) {
	p := NewMicrosoftProvider(OAuthProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"openid", "profile", "email", "User.Read"},
	}, "common")

	assert.Equal(t, "microsoft", p.GetProvider())
	assert.Equal(t, "Microsoft", p.GetDisplayName())
	assert.NotEmpty(t, p.config.Endpoint.AuthURL)
	assert.NotEmpty(t, p.config.Endpoint.TokenURL)
}

func TestGetMicrosoftUserInfo_Success_WithMail(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0/me" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(microsoftUser{
				ID:                "obj-uuid-123",
				UserPrincipalName: "jane.doe@corp.onmicrosoft.com",
				DisplayName:       "Jane Doe",
				Mail:              "jane.doe@corp.com",
			})
			return
		}
		http.NotFound(w, r)
	})

	p := NewMicrosoftProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"}, "common")
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "obj-uuid-123", info.ProviderUserID)
	assert.Equal(t, "jane.doe", info.Username) // split on @
	assert.Equal(t, "Jane Doe", info.FullName)
	assert.Equal(t, "jane.doe@corp.com", info.Email) // mail preferred over UPN
}

func TestGetMicrosoftUserInfo_Success_FallsBackToUPN(t *testing.T) {
	// When mail is empty, userPrincipalName is used as the email address.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0/me" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(microsoftUser{
				ID:                "obj-uuid-456",
				UserPrincipalName: "john@example.com",
				DisplayName:       "John Smith",
				Mail:              "", // empty
			})
			return
		}
		http.NotFound(w, r)
	})

	p := NewMicrosoftProvider(
		OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"},
		"tenantid",
	)
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "john@example.com", info.Email)
	assert.Equal(t, "john", info.Username)
}

func TestGetMicrosoftUserInfo_FullNameFromNameParts(t *testing.T) {
	// When DisplayName is empty, full name is assembled from given + surname.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0/me" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(microsoftUser{
				ID:                "uuid",
				UserPrincipalName: "alice@example.com",
				DisplayName:       "",
				GivenName:         "Alice",
				Surname:           "Wonder",
			})
			return
		}
		http.NotFound(w, r)
	})

	p := NewMicrosoftProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"}, "common")
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.NoError(t, err)
	assert.Equal(t, "Alice Wonder", info.FullName)
}

func TestGetMicrosoftUserInfo_NoEmail(t *testing.T) {
	// Both mail and userPrincipalName are empty → error.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0/me" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(microsoftUser{ID: "uuid"})
			return
		}
		http.NotFound(w, r)
	})

	p := NewMicrosoftProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"}, "common")
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "no email address")
}

func TestGetMicrosoftUserInfo_NonOKStatus(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken"}}`))
	})

	p := NewMicrosoftProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"}, "common")
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "failed to get Microsoft user info")
}

func TestGetMicrosoftUserInfo_InvalidJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	})

	p := NewMicrosoftProvider(OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"}, "common")
	info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())

	require.Error(t, err)
	assert.Nil(t, info)
}
