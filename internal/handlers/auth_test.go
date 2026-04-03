package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoginErrorMessages_KnownKeys(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"session_timeout", "Your session has expired due to inactivity. Please sign in again."},
		{
			"session_invalid",
			"Your session is invalid or may have been accessed from a different device. Please sign in again.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			assert.Equal(t, tc.want, loginErrorMessages[tc.key])
		})
	}
}

func TestLoginErrorMessages_UnknownKeyReturnsEmpty(t *testing.T) {
	// Ensures arbitrary user-supplied values cannot be rendered as flash messages.
	injections := []string{
		"arbitrary_text",
		"Your account is locked. Call 1-800-SCAM",
		"<script>alert(1)</script>",
		"",
	}
	for _, key := range injections {
		assert.Empty(t, loginErrorMessages[key], "unknown key %q must return empty string", key)
	}
}
