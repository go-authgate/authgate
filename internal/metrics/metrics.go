package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Ensure Metrics implements Recorder interface at compile time
var _ Recorder = (*Metrics)(nil)

// Metrics holds all Prometheus metrics for the application
type Metrics struct {
	// OAuth Device Flow Metrics
	DeviceCodesTotal                *prometheus.CounterVec
	DeviceCodesAuthorizedTotal      prometheus.Counter
	DeviceCodeValidationTotal       *prometheus.CounterVec
	DeviceCodesActive               prometheus.Gauge
	DeviceCodesPendingAuthorization prometheus.Gauge
	DeviceCodeAuthorizationDuration prometheus.Histogram

	// Token Metrics
	TokensIssuedTotal       *prometheus.CounterVec
	TokensRevokedTotal      *prometheus.CounterVec
	TokensRefreshedTotal    *prometheus.CounterVec
	TokenValidationTotal    *prometheus.CounterVec
	TokensActive            *prometheus.GaugeVec
	TokenGenerationDuration *prometheus.HistogramVec
	TokenValidationDuration *prometheus.HistogramVec

	// Authentication Metrics
	AuthAttemptsTotal       *prometheus.CounterVec
	AuthLoginTotal          *prometheus.CounterVec
	AuthLogoutTotal         prometheus.Counter
	AuthOAuthCallbackTotal  *prometheus.CounterVec
	AuthLoginDuration       *prometheus.HistogramVec
	AuthExternalAPIDuration *prometheus.HistogramVec

	// Session Metrics
	SessionsActive           prometheus.Gauge
	SessionsCreatedTotal     prometheus.Counter
	SessionsExpiredTotal     *prometheus.CounterVec
	SessionsInvalidatedTotal *prometheus.CounterVec
	SessionDuration          prometheus.Histogram

	// HTTP Request Metrics
	HTTPRequestsTotal    *prometheus.CounterVec
	HTTPRequestDuration  *prometheus.HistogramVec
	HTTPRequestsInFlight prometheus.Gauge

	// Database Query Metrics
	DatabaseQueryErrorsTotal *prometheus.CounterVec
}

var (
	defaultMetrics *Metrics
	once           sync.Once
)

// Init initializes metrics based on enabled flag
// If enabled=true, returns Prometheus-based Metrics
// If enabled=false, returns NoopMetrics (zero overhead)
// Uses sync.Once to ensure Prometheus metrics are only registered once
func Init(enabled bool) Recorder {
	if !enabled {
		return NewNoopMetrics()
	}

	once.Do(func() {
		defaultMetrics = initMetrics()
	})
	return defaultMetrics
}

// initMetrics creates and registers all Prometheus metrics
func initMetrics() *Metrics {
	m := &Metrics{
		// OAuth Device Flow Metrics
		DeviceCodesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth_device_codes_total",
				Help: "Total number of device codes generated",
			},
			[]string{"result"}, // success, error
		),
		DeviceCodesAuthorizedTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "oauth_device_codes_authorized_total",
				Help: "Total number of device codes authorized by users",
			},
		),
		DeviceCodeValidationTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth_device_code_validation_total",
				Help: "Total number of device code validations",
			},
			[]string{"result"}, // success, expired, invalid, pending
		),
		DeviceCodesActive: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "oauth_device_codes_active",
				Help: "Current number of active device codes",
			},
		),
		DeviceCodesPendingAuthorization: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "oauth_device_codes_pending_authorization",
				Help: "Current number of device codes pending user authorization",
			},
		),
		DeviceCodeAuthorizationDuration: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "oauth_device_code_authorization_duration_seconds",
				Help:    "Time taken for user to authorize a device code",
				Buckets: prometheus.DefBuckets,
			},
		),

		// Token Metrics
		TokensIssuedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth_tokens_issued_total",
				Help: "Total number of tokens issued",
			},
			[]string{
				"token_type",
				"grant_type",
			}, // token_type: access, refresh; grant_type: device_code, refresh_token
		),
		TokensRevokedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth_tokens_revoked_total",
				Help: "Total number of tokens revoked",
			},
			[]string{"reason"}, // user_request, admin, rotation, security
		),
		TokensRefreshedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth_tokens_refreshed_total",
				Help: "Total number of token refresh attempts",
			},
			[]string{"result"}, // success, error
		),
		TokenValidationTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth_token_validation_total",
				Help: "Total number of token validations",
			},
			[]string{"result"}, // valid, invalid, expired
		),
		TokensActive: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "oauth_tokens_active",
				Help: "Current number of active tokens",
			},
			[]string{"token_type"}, // access, refresh
		),
		TokenGenerationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "oauth_token_generation_duration_seconds",
				Help:    "Time taken to generate tokens",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"provider"}, // local, http_api
		),
		TokenValidationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "oauth_token_validation_duration_seconds",
				Help:    "Time taken to validate tokens",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"provider"}, // local, http_api
		),

		// Authentication Metrics
		AuthAttemptsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_attempts_total",
				Help: "Total number of authentication attempts",
			},
			[]string{
				"method",
				"result",
			}, // method: local, http_api, oauth; result: success, failure
		),
		AuthLoginTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_login_total",
				Help: "Total number of login attempts",
			},
			[]string{
				"auth_source",
				"result",
			}, // auth_source: local, http_api, microsoft, github, gitea; result: success, failure
		),
		AuthLogoutTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "auth_logout_total",
				Help: "Total number of logouts",
			},
		),
		AuthOAuthCallbackTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_oauth_callback_total",
				Help: "Total number of OAuth callback attempts",
			},
			[]string{
				"provider",
				"result",
			}, // provider: microsoft, github, gitea; result: success, error
		),
		AuthLoginDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_login_duration_seconds",
				Help:    "Time taken to complete login",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"}, // local, http_api, oauth
		),
		AuthExternalAPIDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "auth_external_api_duration_seconds",
				Help:    "Time taken for external API authentication calls",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"provider"}, // http_api
		),

		// Session Metrics
		SessionsActive: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "sessions_active",
				Help: "Current number of active sessions",
			},
		),
		SessionsCreatedTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "sessions_created_total",
				Help: "Total number of sessions created",
			},
		),
		SessionsExpiredTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sessions_expired_total",
				Help: "Total number of sessions expired",
			},
			[]string{"reason"}, // timeout, idle_timeout, logout, fingerprint_mismatch
		),
		SessionsInvalidatedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sessions_invalidated_total",
				Help: "Total number of sessions invalidated",
			},
			[]string{"reason"}, // security, admin
		),
		SessionDuration: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name: "session_duration_seconds",
				Help: "Duration of user sessions",
				Buckets: []float64{
					60,
					300,
					600,
					1800,
					3600,
					7200,
					14400,
					28800,
				}, // 1m, 5m, 10m, 30m, 1h, 2h, 4h, 8h
			},
		),

		// HTTP Request Metrics
		HTTPRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "http_request_duration_seconds",
				Help: "HTTP request latency in seconds",
				Buckets: []float64{
					0.001,
					0.005,
					0.010,
					0.025,
					0.050,
					0.100,
					0.250,
					0.500,
					1.0,
					2.5,
					5.0,
					10.0,
				},
			},
			[]string{"method", "path"},
		),
		HTTPRequestsInFlight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "http_requests_in_flight",
				Help: "Current number of HTTP requests being served",
			},
		),

		// Database Query Metrics
		DatabaseQueryErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "database_query_errors_total",
				Help: "Total number of database query errors during metric collection",
			},
			[]string{"operation"}, // count_access_tokens, count_refresh_tokens, count_device_codes
		),
	}

	return m
}

// GetMetrics returns the global metrics instance
//
// Deprecated: Use Init(true) instead
func GetMetrics() *Metrics {
	if defaultMetrics == nil {
		once.Do(func() {
			defaultMetrics = initMetrics()
		})
	}
	return defaultMetrics
}
