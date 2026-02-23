package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	resultSuccess = "success"
	resultError   = "error"
	resultFailure = "failure"
)

// HTTPMetricsMiddleware creates a Gin middleware that records HTTP metrics
func HTTPMetricsMiddleware(m Recorder) gin.HandlerFunc {
	// If NoopMetrics, return a lightweight middleware that does nothing
	if _, ok := m.(*NoopMetrics); ok {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Type assert to concrete Metrics for Prometheus access
	metrics, ok := m.(*Metrics)
	if !ok {
		// Fallback if unknown implementation
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		// Skip metrics endpoint to avoid self-recording
		if c.Request.URL.Path == "/metrics" {
			c.Next()
			return
		}

		start := time.Now()

		// Increment in-flight counter
		metrics.HTTPRequestsInFlight.Inc()
		defer metrics.HTTPRequestsInFlight.Dec()

		// Process request
		c.Next()

		// Record metrics after request completes
		duration := time.Since(start).Seconds()
		method := c.Request.Method
		path := normalizePath(c.FullPath()) // Use route pattern, not actual path
		status := strconv.Itoa(c.Writer.Status())

		// Record request count
		metrics.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()

		// Record request duration
		metrics.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
	}
}

// normalizePath converts the actual request path to route pattern
// Returns the route pattern (e.g., "/users/:id") or the path itself if no match
func normalizePath(fullPath string) string {
	if fullPath == "" {
		return "unknown"
	}
	return fullPath
}

// RecordOAuthDeviceCodeGenerated records device code generation
func (m *Metrics) RecordOAuthDeviceCodeGenerated(success bool) {
	result := resultSuccess
	if !success {
		result = resultError
	}
	m.DeviceCodesTotal.WithLabelValues(result).Inc()

	if success {
		m.DeviceCodesActive.Inc()
		m.DeviceCodesPendingAuthorization.Inc()
	}
}

// RecordOAuthDeviceCodeAuthorized records device code authorization
func (m *Metrics) RecordOAuthDeviceCodeAuthorized(authorizationTime time.Duration) {
	m.DeviceCodesAuthorizedTotal.Inc()
	m.DeviceCodesPendingAuthorization.Dec()
	m.DeviceCodeAuthorizationDuration.Observe(authorizationTime.Seconds())
}

// RecordOAuthDeviceCodeValidation records device code validation result
func (m *Metrics) RecordOAuthDeviceCodeValidation(result string) {
	// result: success, expired, invalid, pending
	m.DeviceCodeValidationTotal.WithLabelValues(result).Inc()

	// Decrease active count when device code is consumed or expired
	if result == resultSuccess || result == "expired" {
		m.DeviceCodesActive.Dec()
		if result == resultSuccess {
			m.DeviceCodesPendingAuthorization.Dec()
		}
	}
}

// RecordTokenIssued records token issuance
func (m *Metrics) RecordTokenIssued(
	tokenType, grantType string,
	generationTime time.Duration,
	provider string,
) {
	m.TokensIssuedTotal.WithLabelValues(tokenType, grantType).Inc()
	m.TokensActive.WithLabelValues(tokenType).Inc()
	m.TokenGenerationDuration.WithLabelValues(provider).Observe(generationTime.Seconds())
}

// RecordTokenRevoked records token revocation
func (m *Metrics) RecordTokenRevoked(tokenType, reason string) {
	m.TokensRevokedTotal.WithLabelValues(reason).Inc()
	m.TokensActive.WithLabelValues(tokenType).Dec()
}

// RecordTokenRefresh records token refresh attempt
func (m *Metrics) RecordTokenRefresh(success bool) {
	result := resultSuccess
	if !success {
		result = resultError
	}
	m.TokensRefreshedTotal.WithLabelValues(result).Inc()
}

// RecordTokenValidation records token validation
func (m *Metrics) RecordTokenValidation(result string, duration time.Duration, provider string) {
	// result: valid, invalid, expired
	m.TokenValidationTotal.WithLabelValues(result).Inc()
	m.TokenValidationDuration.WithLabelValues(provider).Observe(duration.Seconds())
}

// RecordAuthAttempt records authentication attempt
func (m *Metrics) RecordAuthAttempt(method string, success bool, duration time.Duration) {
	result := "success"
	if !success {
		result = "failure"
	}
	m.AuthAttemptsTotal.WithLabelValues(method, result).Inc()
	m.AuthLoginDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordLogin records login attempt
func (m *Metrics) RecordLogin(authSource string, success bool) {
	result := resultSuccess
	if !success {
		result = resultFailure
	}
	m.AuthLoginTotal.WithLabelValues(authSource, result).Inc()

	if success {
		m.SessionsCreatedTotal.Inc()
		m.SessionsActive.Inc()
	}
}

// RecordLogout records logout
func (m *Metrics) RecordLogout(sessionDuration time.Duration) {
	m.AuthLogoutTotal.Inc()
	m.SessionsActive.Dec()
	m.SessionsExpiredTotal.WithLabelValues("logout").Inc()
	m.SessionDuration.Observe(sessionDuration.Seconds())
}

// RecordOAuthCallback records OAuth callback
func (m *Metrics) RecordOAuthCallback(provider string, success bool) {
	result := resultSuccess
	if !success {
		result = resultError
	}
	m.AuthOAuthCallbackTotal.WithLabelValues(provider, result).Inc()
}

// RecordExternalAPICall records external API call duration
func (m *Metrics) RecordExternalAPICall(provider string, duration time.Duration) {
	m.AuthExternalAPIDuration.WithLabelValues(provider).Observe(duration.Seconds())
}

// RecordSessionExpired records session expiration
func (m *Metrics) RecordSessionExpired(reason string, duration time.Duration) {
	m.SessionsActive.Dec()
	m.SessionsExpiredTotal.WithLabelValues(reason).Inc()
	m.SessionDuration.Observe(duration.Seconds())
}

// RecordSessionInvalidated records session invalidation
func (m *Metrics) RecordSessionInvalidated(reason string) {
	m.SessionsActive.Dec()
	m.SessionsInvalidatedTotal.WithLabelValues(reason).Inc()
}

// SetActiveTokensCount sets the current count of active tokens (for periodic updates)
func (m *Metrics) SetActiveTokensCount(tokenType string, count int) {
	m.TokensActive.WithLabelValues(tokenType).Set(float64(count))
}

// SetActiveDeviceCodesCount sets the current count of active device codes (for periodic updates)
func (m *Metrics) SetActiveDeviceCodesCount(total, pending int) {
	m.DeviceCodesActive.Set(float64(total))
	m.DeviceCodesPendingAuthorization.Set(float64(pending))
}

// SetActiveSessionsCount sets the current count of active sessions (for periodic updates)
func (m *Metrics) SetActiveSessionsCount(count int) {
	m.SessionsActive.Set(float64(count))
}

// RecordDatabaseQueryError records a database query error during metric collection
func (m *Metrics) RecordDatabaseQueryError(operation string) {
	m.DatabaseQueryErrorsTotal.WithLabelValues(operation).Inc()
}

// String formats the metrics for logging
func (m *Metrics) String() string {
	return "Metrics{DeviceCodes: active, Tokens: active, HTTP: enabled}"
}
