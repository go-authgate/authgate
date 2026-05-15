package handlers

import (
	"testing"

	"github.com/go-authgate/authgate/internal/models"

	"github.com/stretchr/testify/assert"
)

// TestIntrospectAudience covers the rules for the `aud` field on RFC 7662
// introspection responses: it must mirror what the signed JWT actually
// carries, NOT just whatever happens to be persisted on the row. In
// particular, refresh-token rows persist the granted resource for §2.2
// subset checks, but the refresh JWT itself is signed with nil audience and
// falls back to JWTAudience — reporting the persisted Resource as `aud`
// would diverge from the JWT and let resource servers wrongly treat a
// refresh token as if it had been issued for them.
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
			name: "refresh token with persisted resource still reports JWTAudience",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryRefresh,
				// Persisted for §2.2 subset checks; NOT the JWT aud.
				Resource: models.StringArray{"https://mcp.example.com"},
			},
			defaultAud: []string{"static.example.com"},
			want:       "static.example.com",
		},
		{
			name: "refresh token with persisted resource and empty JWTAudience → nil",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryRefresh,
				Resource:      models.StringArray{"https://mcp.example.com"},
			},
			defaultAud: nil,
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
