package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	storetypes "github.com/go-authgate/authgate/internal/store/types"
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
	// Construct the service struct directly (without starting the worker)
	// so we can populate the channel deterministically before the drain runs.
	s := setupTestStore(t)
	svc := &AuditService{
		store:         s,
		bufferSize:    100,
		logChan:       make(chan *models.AuditLog, 100),
		batchBuffer:   make([]*models.AuditLog, 0, 100),
		eventsDropped: getAuditEventsDroppedCounter(),
	}

	// Populate the channel before the worker starts
	const numEntries = 5
	for i := range numEntries {
		svc.logChan <- &models.AuditLog{
			ID:        fmt.Sprintf("drain-test-%d", i),
			EventType: models.EventAccessTokenIssued,
			Severity:  models.SeverityInfo,
			Action:    "drain-test",
		}
	}

	// Now start the worker and immediately shut down
	svc.batchTicker = time.NewTicker(1 * time.Second)
	svc.wg.Add(1)
	go svc.worker()

	err := svc.Shutdown(context.Background())
	require.NoError(t, err)

	// Verify entries were persisted to the store
	logs, _, err := s.GetAuditLogsPaginated(
		storetypes.PaginationParams{Page: 1, PageSize: 10},
		storetypes.AuditLogFilters{},
	)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(logs), numEntries, "all drain-test entries should be persisted")
}
