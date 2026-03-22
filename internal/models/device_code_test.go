package models

import (
	"testing"
	"time"
)

func TestDeviceCode_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(30 * time.Minute),
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
		{
			name:      "expires far in the future",
			expiresAt: time.Now().Add(24 * time.Hour),
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DeviceCode{ExpiresAt: tt.expiresAt}
			if got := d.IsExpired(); got != tt.want {
				t.Errorf("DeviceCode.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}
