package client

import (
	"fmt"
	"time"

	httpclient "github.com/appleboy/go-httpclient"
	retry "github.com/appleboy/go-httpretry"
)

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
	// Create HTTP client with automatic authentication
	client, err := httpclient.NewAuthClient(
		authMode,
		authSecret,
		httpclient.WithTimeout(timeout),
		httpclient.WithHeaderName(authHeader),
		httpclient.WithInsecureSkipVerify(insecureSkipVerify),
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
