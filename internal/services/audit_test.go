package services

import (
	"testing"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestMaskSensitiveDetails_FullRedaction(t *testing.T) {
	cases := []struct {
		key string
	}{
		{"password"},
		{"client_secret"},
		{"token"},
		{"access_token"},
		{"refresh_token"},
		{"secret"},
		{"my_secret_key"}, // substring match
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			details := models.AuditDetails{tc.key: "sensitive-value"}
			result := maskSensitiveDetails(details)
			assert.Equal(t, "***REDACTED***", result[tc.key])
		})
	}
}

func TestMaskSensitiveDetails_PartialMask(t *testing.T) {
	cases := []struct {
		key   string
		value string
		want  string
	}{
		// token_id contains "token" substring but must NOT be fully redacted;
		// partial masking must take priority.
		{"token_id", "abcdefgh1234567890xyz", "abcdefgh...0xyz"},
		{"device_code", "abcdefgh1234567890xyz", "abcdefgh...0xyz"},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			details := models.AuditDetails{tc.key: tc.value}
			result := maskSensitiveDetails(details)
			assert.Equal(t, tc.want, result[tc.key],
				"partial-mask should take priority over full redaction for %q", tc.key)
		})
	}
}

func TestMaskSensitiveDetails_PartialMask_ShortValue(t *testing.T) {
	// Values <= 12 chars don't satisfy the partial-mask length threshold, so
	// they fall through to isSensitiveField. token_id contains the "token"
	// substring and is therefore fully redacted rather than kept as-is.
	details := models.AuditDetails{"token_id": "short"}
	result := maskSensitiveDetails(details)
	assert.Equal(t, "***REDACTED***", result["token_id"])
}

func TestMaskSensitiveDetails_PlainField(t *testing.T) {
	details := models.AuditDetails{"username": "alice", "action": "login"}
	result := maskSensitiveDetails(details)
	assert.Equal(t, "alice", result["username"])
	assert.Equal(t, "login", result["action"])
}

func TestMaskSensitiveDetails_Nil(t *testing.T) {
	assert.Nil(t, maskSensitiveDetails(nil))
}
