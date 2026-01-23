package retry_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/appleboy/authgate/internal/retry"
)

// Example_basic demonstrates basic usage with default configuration
func Example_basic() {
	// Create a retry client with default settings
	// (3 retries, 1s initial delay, 10s max delay, 2.0 multiplier)
	client := retry.NewClient()

	// Create a request
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/data", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Execute with automatic retries
	resp, err := client.Do(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Request succeeded")
	}
}

// Example_customConfiguration demonstrates custom retry configuration
func Example_customConfiguration() {
	// Create a retry client with custom settings
	client := retry.NewClient(
		retry.WithMaxRetries(5),                           // Retry up to 5 times
		retry.WithInitialRetryDelay(500*time.Millisecond), // Start with 500ms delay
		retry.WithMaxRetryDelay(30*time.Second),           // Cap delay at 30s
		retry.WithRetryDelayMultiple(3.0),                 // Triple delay each time
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://api.example.com/submit",
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %d\n", resp.StatusCode)
}

// Example_withTimeout demonstrates using context timeout
func Example_withTimeout() {
	client := retry.NewClient(
		retry.WithMaxRetries(10),
		retry.WithInitialRetryDelay(2*time.Second),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/data", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set overall timeout for the operation (including retries)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Do(ctx, req)
	if err != nil {
		// May be context deadline exceeded if retries take too long
		log.Printf("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Request completed within timeout")
}

// Example_customHTTPClient demonstrates using a custom http.Client
func Example_customHTTPClient() {
	// Create a custom http.Client with specific settings
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Use the custom client with retry logic
	client := retry.NewClient(
		retry.WithHTTPClient(httpClient),
		retry.WithMaxRetries(3),
		retry.WithInitialRetryDelay(1*time.Second),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/data", nil)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response received: %d\n", resp.StatusCode)
}

// Example_customRetryChecker demonstrates custom retry logic
func Example_customRetryChecker() {
	// Custom checker that also retries on 403 Forbidden
	customChecker := func(err error, resp *http.Response) bool {
		if err != nil {
			return true // Retry on network errors
		}
		if resp == nil {
			return false
		}

		// Retry on 5xx, 429, and also 403
		statusCode := resp.StatusCode
		return statusCode >= 500 ||
			statusCode == http.StatusTooManyRequests ||
			statusCode == http.StatusForbidden
	}

	client := retry.NewClient(
		retry.WithRetryableChecker(customChecker),
		retry.WithMaxRetries(3),
		retry.WithInitialRetryDelay(1*time.Second),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/data", nil)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Final status: %d\n", resp.StatusCode)
}

// Example_noRetries demonstrates disabling retries
func Example_noRetries() {
	// Set maxRetries to 0 to disable retries
	client := retry.NewClient(
		retry.WithMaxRetries(0),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/data", nil)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Println("Request executed once (no retries)")
}
