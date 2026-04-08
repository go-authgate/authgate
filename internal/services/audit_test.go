package services

import (
	"context"
	"testing"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestBuildAuditLog_EnrichesRequestMetadataFromContext(t *testing.T) {
	svc := &AuditService{}

	ctx := context.Background()
	ctx = util.SetIPContext(ctx, "10.0.0.1")
	ctx = util.SetRequestMetadataContext(ctx, "Mozilla/5.0", "/oauth/token", "POST")

	entry := core.AuditLogEntry{
		EventType: models.EventAccessTokenIssued,
		Severity:  models.SeverityInfo,
		Action:    "test",
		Success:   true,
	}

	result := svc.buildAuditLog(ctx, entry)

	assert.Equal(t, "10.0.0.1", result.ActorIP)
	assert.Equal(t, "Mozilla/5.0", result.UserAgent)
	assert.Equal(t, "/oauth/token", result.RequestPath)
	assert.Equal(t, "POST", result.RequestMethod)
}

func TestBuildAuditLog_DoesNotOverrideExplicitValues(t *testing.T) {
	svc := &AuditService{}

	ctx := context.Background()
	ctx = util.SetIPContext(ctx, "10.0.0.1")
	ctx = util.SetRequestMetadataContext(ctx, "Mozilla/5.0", "/oauth/token", "POST")

	entry := core.AuditLogEntry{
		EventType:     models.EventAccessTokenIssued,
		Severity:      models.SeverityInfo,
		ActorIP:       "192.168.1.1",
		UserAgent:     "custom-agent",
		RequestPath:   "/custom/path",
		RequestMethod: "GET",
		Action:        "test",
		Success:       true,
	}

	result := svc.buildAuditLog(ctx, entry)

	// Explicit values should be preserved, not overwritten by context
	assert.Equal(t, "192.168.1.1", result.ActorIP)
	assert.Equal(t, "custom-agent", result.UserAgent)
	assert.Equal(t, "/custom/path", result.RequestPath)
	assert.Equal(t, "GET", result.RequestMethod)
}

func TestBuildAuditLog_EnrichesUserFromContext(t *testing.T) {
	svc := &AuditService{}

	user := &models.User{
		ID:       "user-123",
		Username: "testuser",
	}
	ctx := models.SetUserContext(context.Background(), user)

	entry := core.AuditLogEntry{
		EventType: models.EventAccessTokenIssued,
		Severity:  models.SeverityInfo,
		Action:    "test",
		Success:   true,
	}

	result := svc.buildAuditLog(ctx, entry)

	assert.Equal(t, "user-123", result.ActorUserID)
	assert.Equal(t, "testuser", result.ActorUsername)
}

func TestShutdown_DrainsLogChan(t *testing.T) {
	// Build the service manually so we can use a real store and avoid nil panics.
	s := setupTestStore(t)
	svc := NewAuditService(s, 100)

	// Directly enqueue entries into logChan (bypass Log to avoid buildAuditLog)
	for i := range 5 {
		svc.logChan <- &models.AuditLog{
			ID:        "drain-test-" + string(rune('0'+i)),
			EventType: models.EventAccessTokenIssued,
			Severity:  models.SeverityInfo,
			Action:    "drain-test",
		}
	}

	// Shutdown should drain all entries without losing them
	err := svc.Shutdown(context.Background())
	require.NoError(t, err)

	// logChan should be empty after shutdown
	assert.Empty(t, svc.logChan)
}
