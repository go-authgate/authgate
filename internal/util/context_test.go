package util

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetIPContext(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Valid IP",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Empty IP",
			ip:       "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			newCtx := SetIPContext(ctx, tt.ip)

			require.NotNil(t, newCtx, "SetIPContext returned nil context")

			retrievedIP := GetIPFromContext(newCtx)
			if tt.expected {
				assert.Equal(t, tt.ip, retrievedIP)
			} else {
				assert.Empty(t, retrievedIP)
			}
		})
	}
}

func TestGetIPFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "Valid IPv4",
			ip:       "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "Valid IPv6",
			ip:       "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
		{
			name:     "Empty context",
			ip:       "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			if tt.ip != "" {
				ctx = SetIPContext(context.Background(), tt.ip)
			} else {
				ctx = context.Background()
			}

			ip := GetIPFromContext(ctx)
			assert.Equal(t, tt.expected, ip)
		})
	}
}

func TestIPContextChaining(t *testing.T) {
	type testKey int
	const testKeyOther testKey = 0

	ctx := context.Background()
	ctx = context.WithValue(ctx, testKeyOther, "other_value")
	ctx = SetIPContext(ctx, "192.168.1.1")

	assert.Equal(t, "192.168.1.1", GetIPFromContext(ctx))
	assert.Equal(t, "other_value", ctx.Value(testKeyOther))
}
