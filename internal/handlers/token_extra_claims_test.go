package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupExtraClaimsTestEnv reuses newTokenTestEnv with extra_claims wired into
// the config so each test case can flip the master switch independently.
func setupExtraClaimsTestEnv(
	t *testing.T,
	enabled bool,
) (*gin.Engine, *store.Store, *config.Config) {
	cfg := defaultTokenTestConfig()
	cfg.ExtraClaimsEnabled = enabled
	cfg.ExtraClaimsMaxRawSize = 4096
	cfg.ExtraClaimsMaxKeys = 16
	cfg.ExtraClaimsMaxValSize = 512
	r, s := newTokenTestEnv(t, cfg)
	return r, s, cfg
}

// decodeUnverifiedClaims pulls claims out of the JWT without signature
// verification — these tests already trust the issuer (the same in-process
// provider) and care only about which keys/values made it into the payload.
func decodeUnverifiedClaims(t *testing.T, tokenString string) jwt.MapClaims {
	t.Helper()
	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := tok.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

func TestExtraClaims_ClientCredentials_HappyPath(t *testing.T) {
	r, s, _ := setupExtraClaimsTestEnv(t, true)
	client, plainSecret := createCCClient(t, s, true, core.ClientTypeConfidential)

	form := url.Values{
		"grant_type":   {"client_credentials"},
		"extra_claims": {`{"tenant":"acme","trace_id":"req-42","feature_flags":["beta"]}`},
	}
	w := postToken(t, r, form, &[2]string{client.ClientID, plainSecret})

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	tokenString, _ := resp["access_token"].(string)
	require.NotEmpty(t, tokenString)

	claims := decodeUnverifiedClaims(t, tokenString)
	assert.Equal(t, "acme", claims["tenant"])
	assert.Equal(t, "req-42", claims["trace_id"])
	flags, ok := claims["feature_flags"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"beta"}, flags)
}

func TestExtraClaims_RejectedWhenFeatureDisabled(t *testing.T) {
	// Default config does not opt into extra_claims; a non-empty parameter
	// must surface a clear error rather than be silently ignored.
	r, s, _ := setupExtraClaimsTestEnv(t, false)
	client, plainSecret := createCCClient(t, s, true, core.ClientTypeConfidential)

	form := url.Values{
		"grant_type":   {"client_credentials"},
		"extra_claims": {`{"tenant":"acme"}`},
	}
	w := postToken(t, r, form, &[2]string{client.ClientID, plainSecret})

	require.Equal(t, http.StatusBadRequest, w.Code, "body=%s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_request", resp["error"])
}

func TestExtraClaims_RejectedReservedKey(t *testing.T) {
	r, s, _ := setupExtraClaimsTestEnv(t, true)
	client, plainSecret := createCCClient(t, s, true, core.ClientTypeConfidential)

	form := url.Values{
		"grant_type":   {"client_credentials"},
		"extra_claims": {`{"iss":"evil","tenant":"acme"}`},
	}
	w := postToken(t, r, form, &[2]string{client.ClientID, plainSecret})

	require.Equal(t, http.StatusBadRequest, w.Code, "body=%s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_request", resp["error"])
}

func TestExtraClaims_RejectedInvalidJSON(t *testing.T) {
	r, s, _ := setupExtraClaimsTestEnv(t, true)
	client, plainSecret := createCCClient(t, s, true, core.ClientTypeConfidential)

	form := url.Values{
		"grant_type":   {"client_credentials"},
		"extra_claims": {`{not json`},
	}
	w := postToken(t, r, form, &[2]string{client.ClientID, plainSecret})

	require.Equal(t, http.StatusBadRequest, w.Code, "body=%s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_request", resp["error"])
}

func TestExtraClaims_OmittedParameterStillWorks(t *testing.T) {
	// When extra_claims is not supplied, the existing happy path must
	// continue to work — the new parameter is purely additive.
	r, s, _ := setupExtraClaimsTestEnv(t, true)
	client, plainSecret := createCCClient(t, s, true, core.ClientTypeConfidential)

	form := url.Values{"grant_type": {"client_credentials"}}
	w := postToken(t, r, form, &[2]string{client.ClientID, plainSecret})

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
}
