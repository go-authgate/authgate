package token

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extraClaimsTestConfig is shared across the tests below to keep generation
// deterministic — no jitter, fixed expiry, fixed secret.
func extraClaimsTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:     "test-secret-key-for-jwt-signing",
		JWTExpiration: time.Hour,
		BaseURL:       "http://localhost:8080",
	}
}

func TestGenerateToken_WithExtraClaims_Merged(t *testing.T) {
	provider, err := NewLocalTokenProvider(extraClaimsTestConfig())
	require.NoError(t, err)

	extra := map[string]any{
		"tenant":        "acme",
		"trace_id":      "abc-123",
		"feature_flags": []any{"beta", "ai-assist"},
	}

	result, err := provider.GenerateToken(
		context.Background(),
		"user-1", "client-1", "read", 0, extra, nil,
	)
	require.NoError(t, err)

	assert.Equal(t, "acme", result.Claims["tenant"])
	assert.Equal(t, "abc-123", result.Claims["trace_id"])
	flags, ok := result.Claims["feature_flags"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"beta", "ai-assist"}, flags)

	// Standard claims must still be present and authoritative.
	assert.Equal(t, "user-1", result.Claims["user_id"])
	assert.Equal(t, "client-1", result.Claims["client_id"])
	assert.Equal(t, "read", result.Claims["scope"])
	assert.Equal(t, TokenCategoryAccess, result.Claims["type"])
}

func TestGenerateToken_ReservedKeysOverriddenByStandard(t *testing.T) {
	// Two-layer defence: ParseExtraClaims at the handler edge rejects
	// reserved keys upfront, but generateJWT must independently override
	// them so a buggy or skipped parser cannot let a forged claim slip out.
	provider, err := NewLocalTokenProvider(extraClaimsTestConfig())
	require.NoError(t, err)

	extra := map[string]any{
		"iss":       "evil",
		"sub":       "spoofed-user",
		"user_id":   "spoofed-user",
		"client_id": "spoofed-client",
		"scope":     "admin",
		"type":      "fake-type",
		"jti":       "fixed-jti",
		"tenant":    "acme", // legitimate custom claim
	}

	result, err := provider.GenerateToken(
		context.Background(),
		"real-user", "real-client", "read", 0, extra, nil,
	)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080", result.Claims["iss"])
	assert.Equal(t, "real-user", result.Claims["sub"])
	assert.Equal(t, "real-user", result.Claims["user_id"])
	assert.Equal(t, "real-client", result.Claims["client_id"])
	assert.Equal(t, "read", result.Claims["scope"])
	assert.Equal(t, TokenCategoryAccess, result.Claims["type"])
	assert.NotEqual(
		t,
		"fixed-jti",
		result.Claims["jti"],
		"jti must be a fresh UUID, not caller-supplied",
	)

	// Legitimate custom claim survives.
	assert.Equal(t, "acme", result.Claims["tenant"])
}

func TestGenerateToken_NilExtraClaims_NoOp(t *testing.T) {
	// Nil extras must not panic and must not introduce stray keys.
	provider, err := NewLocalTokenProvider(extraClaimsTestConfig())
	require.NoError(t, err)

	result, err := provider.GenerateToken(
		context.Background(),
		"user-1", "client-1", "read", 0, nil, nil,
	)
	require.NoError(t, err)

	standardKeys := map[string]bool{
		"user_id": true, "client_id": true, "scope": true, "type": true,
		"exp": true, "iat": true, "iss": true, "sub": true, "jti": true,
	}
	for k := range result.Claims {
		assert.True(t, standardKeys[k], "unexpected claim key: %q", k)
	}
}

func TestRefreshAccessToken_AppliesFreshExtraClaims(t *testing.T) {
	// Refresh has no DB-side persistence of extras: caller-supplied claims on
	// the refresh request fully determine what appears on the new token.
	cfg := extraClaimsTestConfig()
	cfg.RefreshTokenExpiration = 24 * time.Hour
	provider, err := NewLocalTokenProvider(cfg)
	require.NoError(t, err)
	ctx := context.Background()

	original, err := provider.GenerateRefreshToken(
		ctx, "user-1", "client-1", "read", 0,
		map[string]any{"tenant": "old-acme"}, nil,
	)
	require.NoError(t, err)

	// Refresh with a different set of extras — old ones must NOT carry over.
	refreshed, err := provider.RefreshAccessToken(
		ctx, original.TokenString, 0, 0,
		map[string]any{"tenant": "new-acme", "trace_id": "xyz"}, nil, nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "new-acme", refreshed.AccessToken.Claims["tenant"])
	assert.Equal(t, "xyz", refreshed.AccessToken.Claims["trace_id"])

	// Refresh with nil extras — new token has no custom claims at all.
	refreshed2, err := provider.RefreshAccessToken(
		ctx, original.TokenString, 0, 0, nil, nil,
		nil,
	)
	require.NoError(t, err)
	_, hasTenant := refreshed2.AccessToken.Claims["tenant"]
	assert.False(t, hasTenant, "expected stateless refresh, but old tenant claim leaked through")
}

func TestGenerateToken_DropsOIDCOnlyKeysFromAccessToken(t *testing.T) {
	// OIDC-only ID-token claims (nbf/azp/amr/acr/auth_time/nonce/at_hash) have
	// no place in an access token. Even if a caller smuggles them past the
	// parser, generateJWT must drop them before signing.
	provider, err := NewLocalTokenProvider(extraClaimsTestConfig())
	require.NoError(t, err)

	smuggled := map[string]any{
		"nbf":       9999999999,
		"azp":       "evil-azp",
		"amr":       []any{"pwd"},
		"acr":       "0",
		"auth_time": 1234567890,
		"nonce":     "spoofed-nonce",
		"at_hash":   "spoofed-hash",
		"tenant":    "acme", // legitimate custom claim should still survive
	}

	result, err := provider.GenerateToken(
		context.Background(),
		"user-1", "client-1", "read", 0, smuggled, nil,
	)
	require.NoError(t, err)

	for _, k := range []string{"nbf", "azp", "amr", "acr", "auth_time", "nonce", "at_hash"} {
		_, ok := result.Claims[k]
		assert.False(t, ok, "OIDC-only claim %q must not appear in access token", k)
	}
	assert.Equal(t, "acme", result.Claims["tenant"], "non-reserved claim should survive")
}
