package services

import (
	"strings"
	"testing"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/token"

	"github.com/stretchr/testify/assert"
)

func TestBuildClientClaims(t *testing.T) {
	const prefix = "extra"
	projectKey := token.EmittedName(prefix, "project")
	saKey := token.EmittedName(prefix, "service_account")

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
			want: map[string]any{projectKey: "payments-prod"},
		},
		{
			name: "only service account set",
			client: &models.OAuthApplication{
				ServiceAccount: "sa-payments@example.com",
			},
			want: map[string]any{saKey: "sa-payments@example.com"},
		},
		{
			name: "both set",
			client: &models.OAuthApplication{
				Project:        "payments-prod",
				ServiceAccount: "sa-payments@example.com",
			},
			want: map[string]any{
				projectKey: "payments-prod",
				saKey:      "sa-payments@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildClientClaims(tt.client, prefix)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildServerClaims(t *testing.T) {
	domainKey := token.EmittedName("extra", "domain")
	tests := []struct {
		name   string
		domain string
		prefix string
		want   map[string]any
	}{
		{name: "empty domain returns nil", domain: "", prefix: "extra", want: nil},
		{
			name:   "populated domain returns prefixed claim",
			domain: "oa",
			prefix: "extra",
			want:   map[string]any{domainKey: "oa"},
		},
		{
			name:   "verbatim case preserved",
			domain: "OA",
			prefix: "extra",
			want:   map[string]any{domainKey: "OA"},
		},
		{
			name:   "custom prefix produces acme_domain",
			domain: "oa",
			prefix: "acme",
			want:   map[string]any{token.EmittedName("acme", "domain"): "oa"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildServerClaims(tt.domain, tt.prefix))
		})
	}
}

func TestApplyServerClaims_ServerWinsOnCollision(t *testing.T) {
	// Server-attested claims are the absolute floor — they override anything
	// caller- or client-supplied. A future per-client `domain` field could not
	// silently shadow JWT_DOMAIN without changing this precedence.
	domainKey := token.EmittedName("extra", "domain")
	merged := mergeCallerExtraClaims(
		map[string]any{domainKey: "client-set"}, // pretend per-client
		map[string]any{domainKey: "caller-set"}, // caller extra_claims
	)
	final := applyServerClaims(merged, map[string]any{domainKey: "server-set"})
	assert.Equal(t, "server-set", final[domainKey])
}

func TestApplyServerClaims_NilServerLeavesMapUntouched(t *testing.T) {
	// When JWT_DOMAIN is empty, applyServerClaims must not allocate or mutate
	// — existing deployments that don't set the env var see byte-for-byte
	// identical JWT payloads.
	domainKey := token.EmittedName("extra", "domain")
	in := map[string]any{"tenant": "acme"}
	out := applyServerClaims(in, nil)
	assert.Equal(t, in, out)
	_, hasDomain := out[domainKey]
	assert.False(t, hasDomain)

	// Nil base + nil server stays nil — no stray empty allocation.
	assert.Nil(t, applyServerClaims(nil, nil))
}

func TestApplyServerClaims_NilBaseAllocates(t *testing.T) {
	domainKey := token.EmittedName("extra", "domain")
	out := applyServerClaims(nil, map[string]any{domainKey: "oa"})
	assert.Equal(t, map[string]any{domainKey: "oa"}, out)
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
