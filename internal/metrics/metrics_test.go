package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	m := Init(true)
	assert.NotNil(t, m)

	// Type assert to concrete Metrics to access fields
	metrics, ok := m.(*Metrics)
	assert.True(t, ok, "Init(true) should return *Metrics")
	assert.NotNil(t, metrics.DeviceCodesTotal)
	assert.NotNil(t, metrics.TokensIssuedTotal)
	assert.NotNil(t, metrics.AuthAttemptsTotal)
	assert.NotNil(t, metrics.HTTPRequestsTotal)
}

func TestInitNoop(t *testing.T) {
	m := Init(false)
	assert.NotNil(t, m)

	// Type assert to NoopMetrics
	_, ok := m.(*NoopMetrics)
	assert.True(t, ok, "Init(false) should return *NoopMetrics")
}

func TestGetMetrics(t *testing.T) {
	// GetMetrics should return the same instance (already initialized in TestInit)
	m1 := GetMetrics()
	assert.NotNil(t, m1)

	m2 := GetMetrics()
	assert.Equal(t, m1, m2, "GetMetrics should return the same instance")
}

func TestRecordOAuthDeviceCodeGenerated(t *testing.T) {
	m := Init(true)

	m.RecordOAuthDeviceCodeGenerated(true)
	// No error means success - prometheus metrics don't return errors for recording
}

func TestRecordOAuthDeviceCodeAuthorized(t *testing.T) {
	m := Init(true)

	m.RecordOAuthDeviceCodeAuthorized(5 * time.Second)
	// No error means success
}

func TestRecordOAuthDeviceCodeValidation(t *testing.T) {
	m := Init(true)

	// First generate a device code
	m.RecordOAuthDeviceCodeGenerated(true)

	// Then validate it
	m.RecordOAuthDeviceCodeValidation("success")
	// No error means success
}

func TestRecordTokenIssued(t *testing.T) {
	m := Init(true)

	m.RecordTokenIssued("access", "device_code", 100*time.Millisecond, "local")
	m.RecordTokenIssued("refresh", "device_code", 150*time.Millisecond, "local")
	// No error means success
}

func TestRecordTokenRevoked(t *testing.T) {
	m := Init(true)

	// First issue a token
	m.RecordTokenIssued("access", "device_code", 100*time.Millisecond, "local")

	// Then revoke it
	m.RecordTokenRevoked("access", "user_request")
	// No error means success
}

func TestRecordTokenRefresh(t *testing.T) {
	m := Init(true)

	m.RecordTokenRefresh(true)
	m.RecordTokenRefresh(false)
	// No error means success
}

func TestRecordTokenValidation(t *testing.T) {
	m := Init(true)

	m.RecordTokenValidation("valid", 50*time.Millisecond, "local")
	m.RecordTokenValidation("invalid", 30*time.Millisecond, "local")
	m.RecordTokenValidation("expired", 40*time.Millisecond, "local")
	// No error means success
}

func TestRecordAuthAttempt(t *testing.T) {
	m := Init(true)

	m.RecordAuthAttempt("local", true, 200*time.Millisecond)
	m.RecordAuthAttempt("local", false, 150*time.Millisecond)
	m.RecordAuthAttempt("http_api", true, 500*time.Millisecond)
	// No error means success
}

func TestRecordLogin(t *testing.T) {
	m := Init(true)

	m.RecordLogin("local", true)
	m.RecordLogin("local", false)
	m.RecordLogin("microsoft", true)
	// No error means success
}

func TestRecordLogout(t *testing.T) {
	m := Init(true)

	// First create a session
	m.RecordLogin("local", true)

	// Then logout
	m.RecordLogout(3600 * time.Second)
	// No error means success
}

func TestRecordOAuthCallback(t *testing.T) {
	m := Init(true)

	m.RecordOAuthCallback("microsoft", true)
	m.RecordOAuthCallback("github", false)
	// No error means success
}

func TestRecordExternalAPICall(t *testing.T) {
	m := Init(true)

	m.RecordExternalAPICall("http_api", 300*time.Millisecond)
	// No error means success
}

func TestRecordSessionExpired(t *testing.T) {
	m := Init(true)

	// First create a session
	m.RecordLogin("local", true)

	// Then expire it
	m.RecordSessionExpired("timeout", 1800*time.Second)
	// No error means success
}

func TestRecordSessionInvalidated(t *testing.T) {
	m := Init(true)

	// First create a session
	m.RecordLogin("local", true)

	// Then invalidate it
	m.RecordSessionInvalidated("security")
	// No error means success
}

func TestSetActiveTokensCount(t *testing.T) {
	m := Init(true)

	m.SetActiveTokensCount("access", 100)
	m.SetActiveTokensCount("refresh", 50)
	// No error means success
}

func TestSetActiveDeviceCodesCount(t *testing.T) {
	m := Init(true)

	m.SetActiveDeviceCodesCount(20, 5)
	// No error means success
}

func TestSetActiveSessionsCount(t *testing.T) {
	m := Init(true)

	m.SetActiveSessionsCount(42)
	// No error means success
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
		expected string
	}{
		{"empty path", "", "unknown"},
		{"root path", "/", "/"},
		{"health check", "/health", "/health"},
		{"device code", "/oauth/device/code", "/oauth/device/code"},
		{"parameterized", "/users/:id", "/users/:id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePath(tt.fullPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}
