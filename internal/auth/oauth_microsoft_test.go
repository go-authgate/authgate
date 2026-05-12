package auth

import (
	"encoding/json"
	"net/http"
	"strings"
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

	// $select must list every property the response parser reads — verifying
	// the URL guards against future field additions that forget to update it.
	assert.Contains(t, p.apiURL, "$select=", "Graph /me request must use $select")
	for _, field := range []string{
		"id", "userPrincipalName", "displayName", "mail",
		"givenName", "surname",
		"onPremisesSamAccountName", "onPremisesSyncEnabled", "mailNickname",
	} {
		assert.Contains(
			t, p.apiURL, field,
			"apiURL must $select %s for response parsing",
			field,
		)
	}
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
	assert.True(t, info.EmailVerified, "Microsoft Entra ID email is tenant-controlled")
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

func boolPtr(b bool) *bool { return &b }

// TestGetMicrosoftUserInfo_UsernameDerivation exercises pickMicrosoftUsername's
// fallback chain through GetUserInfo: hybrid sAMAccountName → mailNickname →
// email prefix. Also asserts that the request includes the $select clause so
// these properties are actually returned by Graph.
func TestGetMicrosoftUserInfo_UsernameDerivation(t *testing.T) {
	tests := []struct {
		name string
		user microsoftUser
		want string
	}{
		{
			name: "hybrid sync returns sAMAccountName",
			user: microsoftUser{
				ID:                       "uuid-1",
				UserPrincipalName:        "jane.doe@corp.onmicrosoft.com",
				Mail:                     "jane.doe@corp.com",
				OnPremisesSyncEnabled:    boolPtr(true),
				OnPremisesSamAccountName: "mtk12345",
				MailNickname:             "jane.doe",
			},
			want: "mtk12345",
		},
		{
			name: "sync disabled falls back to mailNickname",
			user: microsoftUser{
				ID:                       "uuid-2",
				UserPrincipalName:        "guest@corp.com",
				Mail:                     "guest@external.com",
				OnPremisesSyncEnabled:    boolPtr(false),
				OnPremisesSamAccountName: "stale-sam", // present but must be ignored
				MailNickname:             "guest_external#EXT#",
			},
			want: "guest_external#EXT#",
		},
		{
			name: "sync null falls back to mailNickname",
			user: microsoftUser{
				ID:                "uuid-3",
				UserPrincipalName: "alice@corp.com",
				Mail:              "alice@corp.com",
				// OnPremisesSyncEnabled left nil to model cloud-only accounts.
				MailNickname: "alice",
			},
			want: "alice",
		},
		{
			name: "no SAM, no mailNickname → email prefix",
			user: microsoftUser{
				ID:                "uuid-4",
				UserPrincipalName: "bob@corp.com",
				Mail:              "bob@corp.com",
			},
			want: "bob",
		},
		{
			name: "sync enabled but SAM empty falls through",
			user: microsoftUser{
				ID:                    "uuid-5",
				UserPrincipalName:     "carol@corp.com",
				Mail:                  "carol@corp.com",
				OnPremisesSyncEnabled: boolPtr(true),
				// SAM empty — directory claims sync but did not populate the field.
				MailNickname: "carol-nick",
			},
			want: "carol-nick",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedPath string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.RequestURI()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.user)
			})

			p := NewMicrosoftProvider(
				OAuthProviderConfig{ClientID: "id", ClientSecret: "secret"},
				"common",
			)
			info, err := p.GetUserInfo(contextWithMock(handler), newTestToken())
			require.NoError(t, err)
			require.NotNil(t, info)
			assert.Equal(t, tt.want, info.Username)
			assert.True(
				t,
				strings.Contains(capturedPath, "$select=") &&
					strings.Contains(capturedPath, "onPremisesSamAccountName"),
				"recorded request must include $select with onPremisesSamAccountName; got %q",
				capturedPath,
			)
		})
	}
}
