package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	httpclient "github.com/appleboy/go-httpclient"
	retry "github.com/appleboy/go-httpretry"
)

// CreateOptimizedTransport creates an HTTP transport with optimized connection pool settings
func CreateOptimizedTransport(insecureSkipVerify bool) *http.Transport {
	return &http.Transport{
		// Connection pool settings
		MaxIdleConns:        100,              // Maximum idle connections across all hosts
		MaxIdleConnsPerHost: 10,               // Maximum idle connections per host
		MaxConnsPerHost:     0,                // No limit on total connections per host
		IdleConnTimeout:     90 * time.Second, // How long an idle connection is kept

		// Timeouts
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		// Keep-alive settings
		DisableKeepAlives:  false, // Enable connection reuse
		DisableCompression: false,

		// TLS configuration
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // Configurable for dev/test environments
			MinVersion:         tls.VersionTLS12,
		},

		// Connection settings
		ForceAttemptHTTP2: true, // Enable HTTP/2
	}
}

// CreateRetryClient creates an HTTP client with retry support and authentication.
// This is used for service-to-service communication with external APIs.
func CreateRetryClient(
	authMode, authSecret string,
	timeout time.Duration,
	insecureSkipVerify bool,
	maxRetries int,
	retryDelay, maxRetryDelay time.Duration,
	authHeader string,
) (*retry.Client, error) {
	// Create optimized transport
	transport := CreateOptimizedTransport(insecureSkipVerify)

	// Create HTTP client with automatic authentication and optimized transport
	client, err := httpclient.NewAuthClient(
		authMode,
		authSecret,
		httpclient.WithTimeout(timeout),
		httpclient.WithHeaderName(authHeader),
		httpclient.WithTransport(transport),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth client: %w", err)
	}

	// Wrap with retry client
	retryClient, err := retry.NewRealtimeClient(
		retry.WithHTTPClient(client),
		retry.WithMaxRetries(maxRetries),
		retry.WithInitialRetryDelay(retryDelay),
		retry.WithMaxRetryDelay(maxRetryDelay),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create retry client: %w", err)
	}

	return retryClient, nil
}
