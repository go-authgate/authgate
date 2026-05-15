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
// access token. Access tokens report `tok.Resource` directly — the snapshot
// of what the JWT was actually signed with at issuance time, which the
// service layer populates from the per-request RFC 8707 binding OR a
// snapshot of the static JWTAudience config. Reading the snapshot rather
// than re-deriving from the live config protects resource servers from
// JWT_AUDIENCE rotations that would otherwise change introspection
// responses for already-issued tokens.
func TestIntrospectAudience(t *testing.T) {
	tests := []struct {
		name  string
		token *models.AccessToken
		want  any
	}{
		{
			name: "access token with single resource → string",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryAccess,
				Resource:      models.StringArray{"https://mcp.example.com"},
			},
			want: "https://mcp.example.com",
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
			want: []string{
				"https://mcp1.example.com",
				"https://mcp2.example.com",
			},
		},
		{
			name: "access token snapshot of static JWTAudience persisted as Resource → string",
			// Service layer writes JWTAudience into Resource at issuance when
			// no per-request resource is supplied; introspection just reads
			// what was persisted.
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryAccess,
				Resource:      models.StringArray{"static.example.com"},
			},
			want: "static.example.com",
		},
		{
			name: "access token with empty Resource (neither JWT_AUDIENCE nor RFC 8707) → nil",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryAccess,
			},
			want: nil,
		},
		{
			name: "refresh token always omits aud (token_type=Bearer would mislead RS)",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryRefresh,
				// Persisted for §2.2 subset checks; never reported as aud.
				Resource: models.StringArray{"https://mcp.example.com"},
			},
			want: nil,
		},
		{
			name: "refresh token without resource also omits aud",
			token: &models.AccessToken{
				TokenCategory: models.TokenCategoryRefresh,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := introspectAudience(tt.token)
			assert.Equal(t, tt.want, got)
		})
	}
}
