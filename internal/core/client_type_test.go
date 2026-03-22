package core

import (
	"testing"
)

func TestClientType_String(t *testing.T) {
	tests := []struct {
		name string
		ct   ClientType
		want string
	}{
		{name: "confidential", ct: ClientTypeConfidential, want: "confidential"},
		{name: "public", ct: ClientTypePublic, want: "public"},
		{name: "unknown value", ct: ClientType("unknown"), want: "unknown"},
		{name: "empty", ct: ClientType(""), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.want {
				t.Errorf("ClientType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientType_IsValid(t *testing.T) {
	tests := []struct {
		name string
		ct   ClientType
		want bool
	}{
		{name: "confidential is valid", ct: ClientTypeConfidential, want: true},
		{name: "public is valid", ct: ClientTypePublic, want: true},
		{name: "unknown is invalid", ct: ClientType("unknown"), want: false},
		{name: "empty is invalid", ct: ClientType(""), want: false},
		{name: "uppercase Public is invalid", ct: ClientType("Public"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ct.IsValid(); got != tt.want {
				t.Errorf("ClientType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientType_OrDefault(t *testing.T) {
	tests := []struct {
		name string
		ct   ClientType
		want ClientType
	}{
		{
			name: "confidential returns itself",
			ct:   ClientTypeConfidential,
			want: ClientTypeConfidential,
		},
		{name: "public returns itself", ct: ClientTypePublic, want: ClientTypePublic},
		{
			name: "unknown defaults to confidential",
			ct:   ClientType("unknown"),
			want: ClientTypeConfidential,
		},
		{name: "empty defaults to confidential", ct: ClientType(""), want: ClientTypeConfidential},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ct.OrDefault(); got != tt.want {
				t.Errorf("ClientType.OrDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeClientType(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want ClientType
	}{
		{name: "confidential", raw: "confidential", want: ClientTypeConfidential},
		{name: "public", raw: "public", want: ClientTypePublic},
		{name: "unknown defaults to confidential", raw: "unknown", want: ClientTypeConfidential},
		{name: "empty defaults to confidential", raw: "", want: ClientTypeConfidential},
		{name: "uppercase defaults to confidential", raw: "Public", want: ClientTypeConfidential},
		{
			name: "mixed case defaults to confidential",
			raw:  "Confidential",
			want: ClientTypeConfidential,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeClientType(tt.raw); got != tt.want {
				t.Errorf("NormalizeClientType(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
