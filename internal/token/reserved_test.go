package token

import (
	"errors"
	"testing"
)

func TestIsReservedClaimKey(t *testing.T) {
	reserved := []string{
		"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
		"type", "scope", "user_id", "client_id",
		"azp", "amr", "acr", "auth_time", "nonce", "at_hash",
		ClaimProject, ClaimServiceAccount,
	}
	for _, k := range reserved {
		if !IsReservedClaimKey(k) {
			t.Errorf("expected %q to be reserved", k)
		}
	}

	allowed := []string{"tenant", "trace_id", "department", "role", "feature_flags"}
	for _, k := range allowed {
		if IsReservedClaimKey(k) {
			t.Errorf("expected %q to NOT be reserved", k)
		}
	}
}

func TestValidateExtraClaims(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]any
		wantErr bool
	}{
		{name: "nil map", input: nil, wantErr: false},
		{name: "empty map", input: map[string]any{}, wantErr: false},
		{
			name:    "all custom keys",
			input:   map[string]any{"tenant": "acme", "request_id": "abc"},
			wantErr: false,
		},
		{
			name:    "rejects iss",
			input:   map[string]any{"tenant": "acme", "iss": "evil"},
			wantErr: true,
		},
		{
			name:    "rejects sub",
			input:   map[string]any{"sub": "user-2"},
			wantErr: true,
		},
		{
			name:    "rejects project (system claim)",
			input:   map[string]any{ClaimProject: "fake"},
			wantErr: true,
		},
		{
			name:    "rejects empty key",
			input:   map[string]any{"": "v"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExtraClaims(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrReservedClaimKey) {
					t.Fatalf("expected ErrReservedClaimKey, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}
