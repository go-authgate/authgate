package util

import (
	"reflect"
	"testing"
)

func TestAudienceClaim(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want any
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"single", []string{"https://api.example.com"}, "https://api.example.com"},
		{"multi", []string{"a", "b"}, []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AudienceClaim(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("AudienceClaim(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestAudienceClaimMultiReturnsCopy(t *testing.T) {
	in := []string{"a", "b"}
	got := AudienceClaim(in).([]string)
	got[0] = "mutated"
	if in[0] != "a" {
		t.Fatalf("AudienceClaim mutated input slice: %v", in)
	}
}

func TestAudienceFromClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"missing", map[string]any{}, nil},
		{"empty_string", map[string]any{"aud": ""}, nil},
		{"single_string", map[string]any{"aud": "x"}, []string{"x"}},
		{"string_slice", map[string]any{"aud": []string{"x", "y"}}, []string{"x", "y"}},
		{"any_slice", map[string]any{"aud": []any{"x", "y"}}, []string{"x", "y"}},
		{
			"any_slice_with_blanks",
			map[string]any{"aud": []any{"x", "", "y", 42}},
			[]string{"x", "y"},
		},
		{"unknown_type", map[string]any{"aud": 42}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AudienceFromClaims(tt.claims)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("AudienceFromClaims(%v) = %v, want %v", tt.claims, got, tt.want)
			}
		})
	}
}
