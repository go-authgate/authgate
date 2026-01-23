package retry

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Default retry configuration
const (
	defaultMaxRetries         = 3
	defaultInitialRetryDelay  = 1 * time.Second
	defaultMaxRetryDelay      = 10 * time.Second
	defaultRetryDelayMultiple = 2.0
)

// Client is an HTTP client with automatic retry logic using exponential backoff
type Client struct {
	maxRetries         int
	initialRetryDelay  time.Duration
	maxRetryDelay      time.Duration
	retryDelayMultiple float64
	httpClient         *http.Client
	retryableChecker   RetryableChecker
}

// RetryableChecker determines if an error or response should trigger a retry
type RetryableChecker func(err error, resp *http.Response) bool

// Option configures a Client
type Option func(*Client)

// WithMaxRetries sets the maximum number of retry attempts
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.maxRetries = n
		}
	}
}

// WithInitialRetryDelay sets the initial delay before the first retry
func WithInitialRetryDelay(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.initialRetryDelay = d
		}
	}
}

// WithMaxRetryDelay sets the maximum delay between retries
func WithMaxRetryDelay(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.maxRetryDelay = d
		}
	}
}

// WithRetryDelayMultiple sets the exponential backoff multiplier
func WithRetryDelayMultiple(multiplier float64) Option {
	return func(c *Client) {
		if multiplier > 1.0 {
			c.retryDelayMultiple = multiplier
		}
	}
}

// WithHTTPClient sets a custom http.Client
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithRetryableChecker sets a custom function to determine retryable errors
func WithRetryableChecker(checker RetryableChecker) Option {
	return func(c *Client) {
		if checker != nil {
			c.retryableChecker = checker
		}
	}
}

// NewClient creates a new retry-enabled HTTP client with the given options
func NewClient(opts ...Option) *Client {
	c := &Client{
		maxRetries:         defaultMaxRetries,
		initialRetryDelay:  defaultInitialRetryDelay,
		maxRetryDelay:      defaultMaxRetryDelay,
		retryDelayMultiple: defaultRetryDelayMultiple,
		httpClient:         http.DefaultClient,
		retryableChecker:   DefaultRetryableChecker,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// DefaultRetryableChecker is the default implementation for determining retryable errors
// It retries on network errors and 5xx/429 status codes
func DefaultRetryableChecker(err error, resp *http.Response) bool {
	if err != nil {
		// Network errors, timeouts, connection errors are retryable
		return true
	}

	if resp == nil {
		return false
	}

	// Retry on 5xx server errors and 429 Too Many Requests
	statusCode := resp.StatusCode
	return statusCode >= 500 || statusCode == http.StatusTooManyRequests
}

// Do executes an HTTP request with automatic retry logic using exponential backoff
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	var resp *http.Response
	delay := c.initialRetryDelay

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry (exponential backoff)
			select {
			case <-ctx.Done():
				if lastErr != nil {
					return nil, fmt.Errorf(
						"context cancelled after %d attempts: %w",
						attempt,
						lastErr,
					)
				}
				return nil, ctx.Err()
			case <-time.After(delay):
				// Calculate next delay with exponential backoff
				delay = time.Duration(float64(delay) * c.retryDelayMultiple)
				if delay > c.maxRetryDelay {
					delay = c.maxRetryDelay
				}
			}
		}

		// Clone the request for retry (important: body might be consumed)
		reqClone := req.Clone(ctx)

		resp, lastErr = c.httpClient.Do(reqClone)

		// Check if we should retry
		if !c.retryableChecker(lastErr, resp) {
			// Success or non-retryable error
			return resp, lastErr
		}

		// Close response body before retry to prevent resource leak
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}

	// All retries exhausted
	if lastErr != nil {
		return nil, fmt.Errorf("request failed after %d retries: %w", c.maxRetries, lastErr)
	}

	return resp, lastErr
}
