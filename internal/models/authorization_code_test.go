package models

import (
	"testing"
	"time"
)

func TestAuthorizationCode_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(10 * time.Minute),
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
			a := &AuthorizationCode{ExpiresAt: tt.expiresAt}
			if got := a.IsExpired(); got != tt.want {
				t.Errorf("AuthorizationCode.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationCode_IsUsed(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		usedAt *time.Time
		want   bool
	}{
		{name: "used", usedAt: &now, want: true},
		{name: "not used", usedAt: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthorizationCode{UsedAt: tt.usedAt}
			if got := a.IsUsed(); got != tt.want {
				t.Errorf("AuthorizationCode.IsUsed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationCode_TableName(t *testing.T) {
	a := AuthorizationCode{}
	if got := a.TableName(); got != "authorization_codes" {
		t.Errorf("AuthorizationCode.TableName() = %v, want %v", got, "authorization_codes")
	}
}
