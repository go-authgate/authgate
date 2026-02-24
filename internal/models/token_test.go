package models

import (
	"testing"
	"time"
)

func TestAccessToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "already expired",
			expiresAt: time.Now().Add(-1 * time.Second),
			want:      true,
		},
		{
			name:      "zero time is expired",
			expiresAt: time.Time{},
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &AccessToken{ExpiresAt: tt.expiresAt}
			if got := tok.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessToken_IsActive(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{name: "active", status: "active", want: true},
		{name: "revoked", status: "revoked", want: false},
		{name: "disabled", status: "disabled", want: false},
		{name: "empty", status: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &AccessToken{Status: tt.status}
			if got := tok.IsActive(); got != tt.want {
				t.Errorf("IsActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessToken_IsRevoked(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{name: "revoked", status: "revoked", want: true},
		{name: "active", status: "active", want: false},
		{name: "disabled", status: "disabled", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &AccessToken{Status: tt.status}
			if got := tok.IsRevoked(); got != tt.want {
				t.Errorf("IsRevoked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessToken_IsDisabled(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{name: "disabled", status: "disabled", want: true},
		{name: "active", status: "active", want: false},
		{name: "revoked", status: "revoked", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &AccessToken{Status: tt.status}
			if got := tok.IsDisabled(); got != tt.want {
				t.Errorf("IsDisabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessToken_IsAccessToken(t *testing.T) {
	tests := []struct {
		name     string
		category string
		want     bool
	}{
		{name: "access", category: "access", want: true},
		{name: "refresh", category: "refresh", want: false},
		{name: "empty", category: "", want: false},
		{name: "uppercase is not matched", category: "Access", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &AccessToken{TokenCategory: tt.category}
			if got := tok.IsAccessToken(); got != tt.want {
				t.Errorf("IsAccessToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessToken_IsRefreshToken(t *testing.T) {
	tests := []struct {
		name     string
		category string
		want     bool
	}{
		{name: "refresh", category: "refresh", want: true},
		{name: "access", category: "access", want: false},
		{name: "empty", category: "", want: false},
		{name: "uppercase is not matched", category: "Refresh", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &AccessToken{TokenCategory: tt.category}
			if got := tok.IsRefreshToken(); got != tt.want {
				t.Errorf("IsRefreshToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
