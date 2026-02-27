package util

import (
	"context"
	"testing"
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

			if newCtx == nil {
				t.Fatal("SetIPContext returned nil context")
			}

			// Try to retrieve the IP
			retrievedIP := GetIPFromContext(newCtx)
			if tt.expected {
				if retrievedIP != tt.ip {
					t.Errorf("Expected IP %s, got %s", tt.ip, retrievedIP)
				}
			} else {
				if retrievedIP != "" {
					t.Errorf("Expected empty IP, but got %s", retrievedIP)
				}
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
			if ip != tt.expected {
				t.Errorf("Expected IP %q, got %q", tt.expected, ip)
			}
		})
	}
}

func TestIPContextChaining(t *testing.T) {
	// Test that context values are preserved when chaining
	type testKey int
	const testKeyOther testKey = 0

	ctx := context.Background()
	ctx = context.WithValue(ctx, testKeyOther, "other_value")
	ctx = SetIPContext(ctx, "192.168.1.1")

	// Check IP is accessible
	if GetIPFromContext(ctx) != "192.168.1.1" {
		t.Error("IP context was not preserved")
	}

	// Check other values are accessible
	if val := ctx.Value(testKeyOther); val != "other_value" {
		t.Error("Other context values were not preserved")
	}
}
