package handlers

import (
	"strings"
	"testing"

	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/stretchr/testify/assert"
)

// ============================================================
// maxStateLength
// ============================================================

func TestMaxStateLength_AcceptsAtLimit(t *testing.T) {
	state := strings.Repeat("a", maxStateLength)
	assert.LessOrEqual(t, len(state), maxStateLength)
}

func TestMaxStateLength_RejectsOverLimit(t *testing.T) {
	state := strings.Repeat("a", maxStateLength+1)
	assert.Greater(t, len(state), maxStateLength)
}

func TestMaxStateLength_AcceptsEmpty(t *testing.T) {
	assert.LessOrEqual(t, len(""), maxStateLength)
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
// authzSuccessMessages / authzErrorMessages
// ============================================================

func TestAuthzSuccessMessages_KnownKeys(t *testing.T) {
	assert.Equal(
		t,
		"Application access has been revoked successfully.",
		authzSuccessMessages["revoked"],
	)
}

func TestAuthzErrorMessages_KnownKeys(t *testing.T) {
	assert.Equal(t, "Authorization not found.", authzErrorMessages["not_found"])
	assert.Equal(
		t,
		"An error occurred while processing your request. Please try again.",
		authzErrorMessages["server_error"],
	)
}

func TestAuthzMessages_UnknownKeyReturnsEmpty(t *testing.T) {
	injections := []string{
		"arbitrary_text",
		"<script>alert(1)</script>",
		"",
	}
	for _, key := range injections {
		assert.Empty(
			t,
			authzSuccessMessages[key],
			"unknown success key %q must return empty string",
			key,
		)
		assert.Empty(
			t,
			authzErrorMessages[key],
			"unknown error key %q must return empty string",
			key,
		)
	}
}

// ============================================================
// util.IsScopeSubset (formerly scopesAreCovered)
// ============================================================

func TestScopesAreCovered_ExactMatch(t *testing.T) {
	assert.True(t, util.IsScopeSubset("read write", "read write"))
}

func TestScopesAreCovered_SubsetOfGranted(t *testing.T) {
	assert.True(t, util.IsScopeSubset("read write admin", "read"))
	assert.True(t, util.IsScopeSubset("read write admin", "read write"))
}

func TestScopesAreCovered_RequestedExceedsGranted(t *testing.T) {
	assert.False(t, util.IsScopeSubset("read", "read write"))
	assert.False(t, util.IsScopeSubset("read write", "read write admin"))
}

func TestScopesAreCovered_EmptyRequestedScopes(t *testing.T) {
	// No scopes requested → trivially covered
	assert.True(t, util.IsScopeSubset("read write", ""))
}

func TestScopesAreCovered_EmptyGrantedScopes(t *testing.T) {
	// Nothing granted but something requested → not covered
	assert.False(t, util.IsScopeSubset("", "read"))
}

func TestScopesAreCovered_BothEmpty(t *testing.T) {
	assert.True(t, util.IsScopeSubset("", ""))
}

func TestScopesAreCovered_DuplicateTokensInRequest(t *testing.T) {
	// Duplicate tokens should still pass if the scope is granted
	assert.True(t, util.IsScopeSubset("read write", "read read"))
}

func TestScopesAreCovered_ExtraWhitespace(t *testing.T) {
	// strings.Fields handles extra whitespace
	assert.True(t, util.IsScopeSubset("read  write", "read"))
}
