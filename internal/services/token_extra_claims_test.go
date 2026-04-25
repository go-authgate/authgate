package services

import (
	"strings"
	"testing"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/token"

	"github.com/stretchr/testify/assert"
)

func TestBuildClientClaims(t *testing.T) {
	tests := []struct {
		name   string
		client *models.OAuthApplication
		want   map[string]any
	}{
		{name: "nil client returns nil", client: nil, want: nil},
		{
			name:   "empty fields return nil",
			client: &models.OAuthApplication{},
			want:   nil,
		},
		{
			name: "only project set",
			client: &models.OAuthApplication{
				Project: "payments-prod",
			},
			want: map[string]any{token.ClaimProject: "payments-prod"},
		},
		{
			name: "only service account set",
			client: &models.OAuthApplication{
				ServiceAccount: "sa-payments@example.com",
			},
			want: map[string]any{token.ClaimServiceAccount: "sa-payments@example.com"},
		},
		{
			name: "both set",
			client: &models.OAuthApplication{
				Project:        "payments-prod",
				ServiceAccount: "sa-payments@example.com",
			},
			want: map[string]any{
				token.ClaimProject:        "payments-prod",
				token.ClaimServiceAccount: "sa-payments@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildClientClaims(tt.client)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateProject(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "empty is allowed (optional field)", input: "", wantErr: false},
		{name: "single alnum", input: "a", wantErr: false},
		{name: "kebab case", input: "payments-prod", wantErr: false},
		{name: "underscores and dots", input: "payments_prod.v2", wantErr: false},
		{name: "max length 64", input: strings.Repeat("a", 64), wantErr: false},
		{name: "leading hyphen rejected", input: "-payments", wantErr: true},
		{name: "trailing hyphen rejected", input: "payments-", wantErr: true},
		{name: "spaces rejected", input: "payments prod", wantErr: true},
		{name: "slash rejected", input: "team/payments", wantErr: true},
		{name: "65 chars rejected", input: strings.Repeat("a", 65), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProject(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateServiceAccount(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "empty is allowed", input: "", wantErr: false},
		{name: "bare id", input: "sa-payments", wantErr: false},
		{name: "email-style", input: "sa-payments@example.com", wantErr: false},
		{name: "leading hyphen rejected", input: "-sa", wantErr: true},
		{name: "spaces rejected", input: "sa payments", wantErr: true},
		{name: "256 chars rejected", input: strings.Repeat("a", 256), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServiceAccount(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
