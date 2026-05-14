package util

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func buildResourceList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("https://mcp%d.example.com", i)
	}
	return out
}

func TestValidateResourceIndicators(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []string
		wantErr bool
	}{
		{
			name:  "empty input returns nil",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty slice returns nil",
			input: []string{},
			want:  nil,
		},
		{
			name:  "single absolute https URI",
			input: []string{"https://mcp.example.com"},
			want:  []string{"https://mcp.example.com"},
		},
		{
			name:  "single absolute https URI with path",
			input: []string{"https://mcp.example.com/api"},
			want:  []string{"https://mcp.example.com/api"},
		},
		{
			name:  "multiple resources",
			input: []string{"https://mcp1.example.com", "https://mcp2.example.com"},
			want:  []string{"https://mcp1.example.com", "https://mcp2.example.com"},
		},
		{
			name:  "http scheme is allowed",
			input: []string{"http://mcp.example.com"},
			want:  []string{"http://mcp.example.com"},
		},
		{
			name:    "urn scheme rejected (non-http(s))",
			input:   []string{"urn:example:resource"},
			wantErr: true,
		},
		{
			name:    "javascript scheme rejected",
			input:   []string{"javascript:alert(1)"},
			wantErr: true,
		},
		{
			name:    "data scheme rejected",
			input:   []string{"data:text/plain,hello"},
			wantErr: true,
		},
		{
			name:    "empty string element rejected",
			input:   []string{""},
			wantErr: true,
		},
		{
			name:    "relative URI rejected",
			input:   []string{"/api/foo"},
			wantErr: true,
		},
		{
			name:    "no-scheme URI rejected",
			input:   []string{"mcp.example.com/api"},
			wantErr: true,
		},
		{
			name:    "URI with fragment rejected",
			input:   []string{"https://mcp.example.com/api#fragment"},
			wantErr: true,
		},
		{
			name:    "http with empty host rejected",
			input:   []string{"http:/path"},
			wantErr: true,
		},
		{
			name:    "https with bare scheme-and-opaque rejected",
			input:   []string{"https:foo"},
			wantErr: true,
		},
		{
			name: "URI over length limit rejected",
			input: []string{
				"https://mcp.example.com/" + strings.Repeat("a", MaxResourceURILength),
			},
			wantErr: true,
		},
		{
			name:    "one of many resources rejected fails all",
			input:   []string{"https://mcp.example.com", "https://bad.example.com#frag"},
			wantErr: true,
		},
		{
			name:    "too many resources rejected",
			input:   buildResourceList(MaxResourceIndicators + 1),
			wantErr: true,
		},
		{
			name:  "exactly max resources accepted",
			input: buildResourceList(MaxResourceIndicators),
			want:  buildResourceList(MaxResourceIndicators),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateResourceIndicators(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidResource) {
					t.Fatalf("expected ErrInvalidResource, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}
