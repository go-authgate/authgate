package core

import "time"

// Recorder defines the interface for recording application metrics.
// Implementations include Metrics (Prometheus-based) and NoopMetrics (no-op).
type Recorder interface {
	// OAuth Device Flow
	RecordOAuthDeviceCodeGenerated(success bool)
	RecordOAuthDeviceCodeAuthorized(authorizationTime time.Duration)
	RecordOAuthDeviceCodeValidation(result string)

	// Token Operations
	RecordTokenIssued(tokenType, grantType string, generationTime time.Duration, provider string)
	RecordTokenRevoked(tokenType, reason string)
	RecordTokenRefresh(success bool)
	RecordTokenValidation(result string, duration time.Duration, provider string)

	// Authentication
	RecordAuthAttempt(method string, success bool, duration time.Duration)
	RecordLogin(authSource string, success bool)
	RecordLogout(sessionDuration time.Duration)
	RecordOAuthCallback(provider string, success bool)
	RecordExternalAPICall(provider string, duration time.Duration)

	// Session Management
	RecordSessionExpired(reason string, duration time.Duration)
	RecordSessionInvalidated(reason string)

	// Gauge Setters (for periodic updates)
	SetActiveTokensCount(tokenType string, count int)
	SetActiveDeviceCodesCount(total, pending int)
	SetActiveSessionsCount(count int)

	// Database Operations
	RecordDatabaseQueryError(operation string)
}

// MetricsStore defines the DB operations needed by CacheWrapper.
type MetricsStore interface {
	CountActiveTokensByCategory(category string) (int64, error)
	CountTotalDeviceCodes() (int64, error)
	CountPendingDeviceCodes() (int64, error)
}
