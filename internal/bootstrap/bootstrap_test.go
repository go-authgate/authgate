package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthConfig(t *testing.T) {
	assert.NoError(t, validateAuthConfig(&config.Config{AuthMode: config.AuthModeLocal}))
	assert.NoError(
		t,
		validateAuthConfig(
			&config.Config{AuthMode: config.AuthModeHTTPAPI, HTTPAPIURL: "http://auth.example.com"},
		),
	)

	err := validateAuthConfig(&config.Config{AuthMode: config.AuthModeHTTPAPI})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP_API_URL is required")

	err = validateAuthConfig(&config.Config{AuthMode: "unknown"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid AUTH_MODE")
}

func TestValidateTokenProviderConfig(t *testing.T) {
	assert.NoError(
		t,
		validateTokenProviderConfig(
			&config.Config{TokenProviderMode: config.TokenProviderModeLocal},
		),
	)
	assert.NoError(
		t,
		validateTokenProviderConfig(
			&config.Config{
				TokenProviderMode: config.TokenProviderModeHTTPAPI,
				TokenAPIURL:       "http://token.example.com",
			},
		),
	)

	err := validateTokenProviderConfig(
		&config.Config{TokenProviderMode: config.TokenProviderModeHTTPAPI},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TOKEN_API_URL is required")

	err = validateTokenProviderConfig(&config.Config{TokenProviderMode: "unknown"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOKEN_PROVIDER_MODE")
}

func TestInitializeMetrics(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := &config.Config{MetricsEnabled: enabled}
		m := initializeMetrics(cfg)
		require.NotNil(t, m)
	}
}

func TestInitializeMetricsCacheDisabled(t *testing.T) {
	ctx := context.Background()

	// Metrics disabled - no cache
	c, closer, err := initializeMetricsCache(
		ctx,
		&config.Config{MetricsEnabled: false, MetricsGaugeUpdateEnabled: true},
	)
	require.NoError(t, err)
	assert.Nil(t, c)
	assert.Nil(t, closer)

	// Gauge updates disabled - no cache
	c, closer, err = initializeMetricsCache(
		ctx,
		&config.Config{MetricsEnabled: true, MetricsGaugeUpdateEnabled: false},
	)
	require.NoError(t, err)
	assert.Nil(t, c)
	assert.Nil(t, closer)
}

func TestInitializeMetricsCacheMemory(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{
		MetricsEnabled:            true,
		MetricsGaugeUpdateEnabled: true,
		MetricsCacheType:          config.MetricsCacheTypeMemory,
	}
	c, closer, err := initializeMetricsCache(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.NotNil(t, closer)
	_ = closer()
}

func TestInitializeOAuthProvidersNone(t *testing.T) {
	providers := initializeOAuthProviders(&config.Config{})
	assert.Empty(t, providers)
}

func TestInitializeOAuthProvidersGitHub(t *testing.T) {
	// Missing credentials
	providers := initializeOAuthProviders(&config.Config{
		GitHubOAuthEnabled: true,
		GitHubClientID:     "",
		GitHubClientSecret: "",
	})
	assert.Empty(t, providers)

	// Valid credentials
	providers = initializeOAuthProviders(&config.Config{
		GitHubOAuthEnabled: true,
		GitHubClientID:     "client-id",
		GitHubClientSecret: "client-secret",
	})
	assert.Contains(t, providers, "github")
}

func TestInitializeOAuthProvidersMicrosoft(t *testing.T) {
	// Missing credentials
	providers := initializeOAuthProviders(&config.Config{
		MicrosoftOAuthEnabled: true,
		MicrosoftClientID:     "",
		MicrosoftClientSecret: "",
	})
	assert.Empty(t, providers)

	// Valid credentials
	providers = initializeOAuthProviders(&config.Config{
		MicrosoftOAuthEnabled: true,
		MicrosoftClientID:     "client-id",
		MicrosoftClientSecret: "client-secret",
		MicrosoftTenantID:     "common",
	})
	assert.Contains(t, providers, "microsoft")
}

func TestSetupRateLimitingDisabled(t *testing.T) {
	limiters := setupRateLimiting(&config.Config{EnableRateLimit: false}, nil, nil)
	require.NotNil(t, limiters.login)
	require.NotNil(t, limiters.deviceCode)
	require.NotNil(t, limiters.token)
	require.NotNil(t, limiters.deviceVerify)

	// Verify noop middlewares don't panic
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	assert.NotPanics(t, func() { limiters.login(c) })
}

func TestSetupRateLimitingMemory(t *testing.T) {
	cfg := &config.Config{
		EnableRateLimit:       true,
		RateLimitStore:        "memory",
		LoginRateLimit:        5,
		DeviceCodeRateLimit:   10,
		TokenRateLimit:        20,
		DeviceVerifyRateLimit: 10,
	}
	limiters := setupRateLimiting(cfg, nil, nil)
	require.NotNil(t, limiters.login)
	require.NotNil(t, limiters.deviceCode)
	require.NotNil(t, limiters.token)
	require.NotNil(t, limiters.deviceVerify)
}

func TestGetProviderNames(t *testing.T) {
	// Empty providers
	names := getProviderNames(initializeOAuthProviders(&config.Config{}))
	assert.Empty(t, names)

	// Single provider
	cfg := &config.Config{
		GitHubOAuthEnabled: true,
		GitHubClientID:     "client-id",
		GitHubClientSecret: "client-secret",
	}
	names = getProviderNames(initializeOAuthProviders(cfg))
	assert.Len(t, names, 1)
	assert.Contains(t, names, "github")
}

func TestCreateHTTPServer(t *testing.T) {
	srv := createHTTPServer(
		&config.Config{ServerAddr: ":8080"},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	)
	require.NotNil(t, srv)
	assert.Equal(t, ":8080", srv.Addr)
}

func TestGinModeMap(t *testing.T) {
	assert.Equal(t, gin.ReleaseMode, ginModeMap[true])
	assert.Equal(t, gin.DebugMode, ginModeMap[false])
}

func TestErrorLogger(t *testing.T) {
	el := newErrorLogger()
	require.NotNil(t, el)
	assert.NotNil(t, el.lastErrorTimes)

	// Both calls should not panic
	assert.NotPanics(t, func() { el.logIfNeeded("test_op", assert.AnError) })
	assert.NotPanics(t, func() { el.logIfNeeded("test_op", assert.AnError) })
}
