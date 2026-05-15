package handlers

import (
	"testing"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/stretchr/testify/assert"
)

// TestIntrospectAudience covers the rules for the `aud` field on RFC 7662
// introspection responses. Refresh tokens always omit `aud`: the response's
// `token_type` is hard-coded "Bearer" (matching access tokens), so any
// reported `aud` could be misread by a resource server doing an
// `active && aud=mine` check, accepting a refresh token as if it were an
// access token. Access tokens report the persisted Resource when set,
// otherwise fall back to the configured JWTAudience.
func TestIntrospectAudience(t *testing.T) {
	tests := []struct {
		name       string
		token      *models.AccessToken
		defaultAud []string
		want       any
	}{
		{
			name: "access token with single resource → string",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryAccess,
				Resource:      models.StringArray{"https://mcp.example.com"},
			},
			defaultAud: []string{"static.example.com"},
			want:       "https://mcp.example.com",
		},
		{
			name: "access token with multiple resources → slice",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryAccess,
				Resource: models.StringArray{
					"https://mcp1.example.com",
					"https://mcp2.example.com",
				},
			},
			defaultAud: []string{"static.example.com"},
			want: []string{
				"https://mcp1.example.com",
				"https://mcp2.example.com",
			},
		},
		{
			name: "access token without resource falls back to JWTAudience",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryAccess,
			},
			defaultAud: []string{"static.example.com"},
			want:       "static.example.com",
		},
		{
			name: "access token without resource and empty JWTAudience → nil",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryAccess,
			},
			defaultAud: nil,
			want:       nil,
		},
		{
			name: "refresh token always omits aud (token_type=Bearer would mislead RS)",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryRefresh,
				// Persisted for §2.2 subset checks; never reported as aud.
				Resource: models.StringArray{"https://mcp.example.com"},
			},
			defaultAud: []string{"static.example.com"},
			want:       nil,
		},
		{
			name: "refresh token without resource also omits aud",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryRefresh,
			},
			defaultAud: []string{"static.example.com"},
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := introspectAudience(tt.token, tt.defaultAud)
			assert.Equal(t, tt.want, got)
		})
	}
}
