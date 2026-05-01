package services

import (
	"context"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/token"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeJWTClaims(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := tok.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

func domainTestConfig(domain string) *config.Config {
	return &config.Config{
		DeviceCodeExpiration:             30 * time.Minute,
		PollingInterval:                  5,
		JWTExpiration:                    time.Hour,
		JWTSecret:                        "test-secret-key-for-jwt-signing",
		BaseURL:                          "http://localhost:8080",
		EnableRefreshTokens:              true,
		RefreshTokenExpiration:           24 * time.Hour,
		ClientCredentialsTokenExpiration: time.Hour,
		JWTDomain:                        domain,
	}
}

// assertDomainClaim asserts the issued JWT carries `domain: want` when want is
// non-empty, or that the claim is absent when want is empty.
func assertDomainClaim(t *testing.T, raw, want string) {
	t.Helper()
	claims := decodeJWTClaims(t, raw)
	got, ok := claims[token.ClaimDomain]
	if want == "" {
		assert.False(t, ok, "expected `domain` claim to be omitted, got %v", got)
		return
	}
	assert.Equal(t, want, got)
}

// TestDeviceCodeFlow_DomainClaim covers both the present and absent cases for
// the device-code grant. Auth-code shares generateAndPersistTokenPair, so this
// pins both paths.
func TestDeviceCodeFlow_DomainClaim(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{name: "emits when JWT_DOMAIN set", domain: "oa"},
		{name: "omits when JWT_DOMAIN unset", domain: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := setupTestStore(t)
			svc := createTestTokenService(t, s, domainTestConfig(tt.domain))

			client := createTestClient(t, s, true)
			dc := createAuthorizedDeviceCode(t, s, client.ClientID)

			access, refresh, err := svc.ExchangeDeviceCode(
				context.Background(), dc.DeviceCode, client.ClientID, nil,
			)
			require.NoError(t, err)

			assertDomainClaim(t, access.RawToken, tt.domain)
			assertDomainClaim(t, refresh.RawToken, tt.domain)
		})
	}
}

func TestAuthCodeFlow_EmitsDomainClaim(t *testing.T) {
	s := setupTestStore(t)
	svc := createTestTokenService(t, s, domainTestConfig("oa"))

	client := createTestClient(t, s, true)
	authCode := createTestAuthCodeRecord(t, s, client, "test-user-id")

	access, refresh, _, err := svc.ExchangeAuthorizationCode(
		context.Background(), authCode, nil, nil,
	)
	require.NoError(t, err)

	assertDomainClaim(t, access.RawToken, "oa")
	assertDomainClaim(t, refresh.RawToken, "oa")
}

// TestRefresh_ReResolvesJWTDomain pins the live-config behavior: flipping
// cfg.JWTDomain between issuance and refresh must propagate to the next
// refreshed token, mirroring how project / service_account changes flow.
func TestRefresh_ReResolvesJWTDomain(t *testing.T) {
	s := setupTestStore(t)
	cfg := domainTestConfig("oa")
	cfg.EnableTokenRotation = true // rotation gives us a fresh refresh JWT to decode
	svc := createTestTokenService(t, s, cfg)

	client := createTestClient(t, s, true)
	dc := createAuthorizedDeviceCode(t, s, client.ClientID)

	_, refresh, err := svc.ExchangeDeviceCode(
		context.Background(), dc.DeviceCode, client.ClientID, nil,
	)
	require.NoError(t, err)

	cfg.JWTDomain = "swrd"

	newAccess, newRefresh, err := svc.RefreshAccessToken(
		context.Background(), refresh.RawToken, client.ClientID, "read write", nil,
	)
	require.NoError(t, err)

	assertDomainClaim(t, newAccess.RawToken, "swrd")
	assertDomainClaim(t, newRefresh.RawToken, "swrd")
}

func TestClientCredentialsFlow_DomainClaim(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{name: "emits when JWT_DOMAIN set", domain: "oa"},
		{name: "omits when JWT_DOMAIN unset", domain: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := setupTestStore(t)
			svc := createTestTokenService(t, s, domainTestConfig(tt.domain))

			client, plainSecret := createConfidentialClientWithCCFlow(t, s, true)

			tok, err := svc.IssueClientCredentialsToken(
				context.Background(), client.ClientID, plainSecret, "", nil,
			)
			require.NoError(t, err)

			assertDomainClaim(t, tok.RawToken, tt.domain)
		})
	}
}

// TestServerDomainOverridesCallerExtraClaims is a defense-in-depth check: the
// reserved-key parser already blocks caller-supplied `domain`, but if it ever
// regressed the service-layer applyServerClaims must still write last.
func TestServerDomainOverridesCallerExtraClaims(t *testing.T) {
	cfg := domainTestConfig("oa")
	provider, err := token.NewLocalTokenProvider(cfg)
	require.NoError(t, err)

	merged := mergeCallerExtraClaims(nil, map[string]any{token.ClaimDomain: "evil"})
	merged = applyServerClaims(merged, buildServerClaims(cfg))

	result, err := provider.GenerateToken(
		context.Background(), "u", "c", "read", 0, merged,
	)
	require.NoError(t, err)
	assert.Equal(t, "oa", result.Claims[token.ClaimDomain])
}
