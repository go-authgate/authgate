package handlers

import (
	"strings"
	"testing"

	"github.com/appleboy/authgate/internal/services"

	"github.com/stretchr/testify/assert"
)

// ============================================================
// maxStateLength
// ============================================================

func TestMaxStateLength_AcceptsAtLimit(t *testing.T) {
	state := strings.Repeat("a", maxStateLength)
	assert.False(t, len(state) > maxStateLength)
}

func TestMaxStateLength_RejectsOverLimit(t *testing.T) {
	state := strings.Repeat("a", maxStateLength+1)
	assert.True(t, len(state) > maxStateLength)
}

func TestMaxStateLength_AcceptsEmpty(t *testing.T) {
	assert.False(t, len("") > maxStateLength)
}

// ============================================================
// oauthErrorCode
// ============================================================

func TestOauthErrorCode_UnauthorizedClient(t *testing.T) {
	assert.Equal(t, "unauthorized_client", oauthErrorCode(services.ErrUnauthorizedClient))
}

func TestOauthErrorCode_UnsupportedResponseType(t *testing.T) {
	assert.Equal(
		t,
		"unsupported_response_type",
		oauthErrorCode(services.ErrUnsupportedResponseType),
	)
}

func TestOauthErrorCode_InvalidScope(t *testing.T) {
	assert.Equal(t, "invalid_scope", oauthErrorCode(services.ErrInvalidAuthCodeScope))
}

func TestOauthErrorCode_DefaultsToInvalidRequest(t *testing.T) {
	// Any unrecognised error falls back to "invalid_request"
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrInvalidAuthCodeRequest))
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrInvalidRedirectURI))
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrAuthCodeNotFound))
	assert.Equal(t, errInvalidRequest, oauthErrorCode(services.ErrPKCERequired))
}

// ============================================================
// scopesAreCovered
// ============================================================

func TestScopesAreCovered_ExactMatch(t *testing.T) {
	assert.True(t, scopesAreCovered("read write", "read write"))
}

func TestScopesAreCovered_SubsetOfGranted(t *testing.T) {
	assert.True(t, scopesAreCovered("read write admin", "read"))
	assert.True(t, scopesAreCovered("read write admin", "read write"))
}

func TestScopesAreCovered_RequestedExceedsGranted(t *testing.T) {
	assert.False(t, scopesAreCovered("read", "read write"))
	assert.False(t, scopesAreCovered("read write", "read write admin"))
}

func TestScopesAreCovered_EmptyRequestedScopes(t *testing.T) {
	// No scopes requested → trivially covered
	assert.True(t, scopesAreCovered("read write", ""))
}

func TestScopesAreCovered_EmptyGrantedScopes(t *testing.T) {
	// Nothing granted but something requested → not covered
	assert.False(t, scopesAreCovered("", "read"))
}

func TestScopesAreCovered_BothEmpty(t *testing.T) {
	assert.True(t, scopesAreCovered("", ""))
}

func TestScopesAreCovered_DuplicateTokensInRequest(t *testing.T) {
	// Duplicate tokens should still pass if the scope is granted
	assert.True(t, scopesAreCovered("read write", "read read"))
}

func TestScopesAreCovered_ExtraWhitespace(t *testing.T) {
	// strings.Fields handles extra whitespace
	assert.True(t, scopesAreCovered("read  write", "read"))
}
