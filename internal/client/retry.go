package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	httpclient "github.com/appleboy/go-httpclient"
	retry "github.com/appleboy/go-httpretry"
)

// RetryClientConfig holds configuration for creating a retry-enabled HTTP client.
type RetryClientConfig struct {
	AuthMode           string
	AuthSecret         string
	Timeout            time.Duration
	InsecureSkipVerify bool
	MaxRetries         int
	RetryDelay         time.Duration
	MaxRetryDelay      time.Duration
	AuthHeader         string
}

// CreateOptimizedTransport creates an HTTP transport with optimized connection pool settings.
func CreateOptimizedTransport(insecureSkipVerify bool) *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,

		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // Configurable for dev/test environments
			MinVersion:         tls.VersionTLS12,
		},

		ForceAttemptHTTP2: true,
	}
}

// CreateRetryClient creates an HTTP client with retry support and authentication.
// This is used for service-to-service communication with external APIs.
func CreateRetryClient(cfg RetryClientConfig) (*retry.Client, error) {
	transport := CreateOptimizedTransport(cfg.InsecureSkipVerify)

	client, err := httpclient.NewAuthClient(
		cfg.AuthMode,
		cfg.AuthSecret,
		httpclient.WithTimeout(cfg.Timeout),
		httpclient.WithHeaderName(cfg.AuthHeader),
		httpclient.WithTransport(transport),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth client: %w", err)
	}

	retryClient, err := retry.NewRealtimeClient(
		retry.WithHTTPClient(client),
		retry.WithMaxRetries(cfg.MaxRetries),
		retry.WithInitialRetryDelay(cfg.RetryDelay),
		retry.WithMaxRetryDelay(cfg.MaxRetryDelay),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create retry client: %w", err)
	}

	return retryClient, nil
}
