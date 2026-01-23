# Retry Package

A flexible HTTP client with automatic retry logic using exponential backoff, built with the Functional Options Pattern.

## Features

- **Automatic Retries**: Retries failed requests with configurable exponential backoff
- **Smart Retry Logic**: Default retries on network errors, 5xx server errors, and 429 (Too Many Requests)
- **Flexible Configuration**: Use functional options to customize retry behavior
- **Context Support**: Respects context cancellation and timeouts
- **Custom Retry Logic**: Pluggable retry checker for custom retry conditions
- **Resource Safe**: Automatically closes response bodies before retries to prevent leaks

## Installation

This package is internal to the AuthGate project and located at `internal/retry`.

```go
import "github.com/appleboy/authgate/internal/retry"
```

## Quick Start

### Basic Usage (Default Settings)

```go
// Create a retry client with defaults:
// - 3 max retries
// - 1 second initial delay
// - 10 second max delay
// - 2.0x exponential multiplier
client := retry.NewClient()

req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
resp, err := client.Do(context.Background(), req)
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
```

### Custom Configuration

```go
client := retry.NewClient(
    retry.WithMaxRetries(5),                           // Retry up to 5 times
    retry.WithInitialRetryDelay(500*time.Millisecond), // Start with 500ms delay
    retry.WithMaxRetryDelay(30*time.Second),           // Cap delay at 30s
    retry.WithRetryDelayMultiple(3.0),                 // Triple delay each time
)
```

## Configuration Options

### `WithMaxRetries(n int)`

Sets the maximum number of retry attempts.

```go
client := retry.NewClient(retry.WithMaxRetries(5))
```

### `WithInitialRetryDelay(d time.Duration)`

Sets the initial delay before the first retry.

```go
client := retry.NewClient(retry.WithInitialRetryDelay(500*time.Millisecond))
```

### `WithMaxRetryDelay(d time.Duration)`

Sets the maximum delay between retries (caps exponential backoff).

```go
client := retry.NewClient(retry.WithMaxRetryDelay(30*time.Second))
```

### `WithRetryDelayMultiple(multiplier float64)`

Sets the exponential backoff multiplier.

```go
client := retry.NewClient(retry.WithRetryDelayMultiple(3.0))
```

### `WithHTTPClient(httpClient *http.Client)`

Uses a custom `http.Client` instead of `http.DefaultClient`.

```go
httpClient := &http.Client{
    Timeout: 10 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns: 100,
    },
}
client := retry.NewClient(retry.WithHTTPClient(httpClient))
```

### `WithRetryableChecker(checker RetryableChecker)`

Provides custom logic for determining which errors should trigger retries.

```go
customChecker := func(err error, resp *http.Response) bool {
    if err != nil {
        return true // Always retry network errors
    }
    if resp == nil {
        return false
    }
    // Retry on 5xx, 429, and also 403
    return resp.StatusCode >= 500 ||
           resp.StatusCode == http.StatusTooManyRequests ||
           resp.StatusCode == http.StatusForbidden
}

client := retry.NewClient(retry.WithRetryableChecker(customChecker))
```

## Default Retry Behavior

The `DefaultRetryableChecker` retries in the following cases:

- **Network errors**: Connection refused, timeouts, DNS errors, etc.
- **5xx Server Errors**: 500, 502, 503, 504, etc.
- **429 Too Many Requests**: Rate limiting errors

It does **NOT** retry:

- **4xx Client Errors** (except 429): 400, 401, 403, 404, etc.
- **2xx Success**: 200, 201, 204, etc.
- **3xx Redirects**: 301, 302, 307, etc.

## Exponential Backoff

Retries use exponential backoff to avoid overwhelming the server:

1. **First retry**: Wait `initialRetryDelay` (default: 1s)
2. **Second retry**: Wait `initialRetryDelay * multiplier` (default: 2s)
3. **Third retry**: Wait `initialRetryDelay * multiplier²` (default: 4s)
4. **Subsequent retries**: Continue multiplying until `maxRetryDelay` is reached

Example with defaults:

- Attempt 1: Immediate
- Attempt 2: After 1s
- Attempt 3: After 2s
- Attempt 4: After 4s

## Context Support

The client respects context cancellation and timeouts:

```go
// Overall timeout for the entire operation (including retries)
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

resp, err := client.Do(ctx, req)
if err != nil {
    // May be context.DeadlineExceeded
    log.Printf("Request failed: %v", err)
}
```

## Examples

### Disable Retries

```go
// Set maxRetries to 0 to disable retries
client := retry.NewClient(retry.WithMaxRetries(0))
```

### Aggressive Retries for Critical Requests

```go
client := retry.NewClient(
    retry.WithMaxRetries(10),
    retry.WithInitialRetryDelay(100*time.Millisecond),
    retry.WithMaxRetryDelay(5*time.Second),
    retry.WithRetryDelayMultiple(1.5),
)
```

### Conservative Retries for Background Tasks

```go
client := retry.NewClient(
    retry.WithMaxRetries(2),
    retry.WithInitialRetryDelay(5*time.Second),
    retry.WithMaxRetryDelay(60*time.Second),
    retry.WithRetryDelayMultiple(2.0),
)
```

### Custom Retry Logic for Authentication Tokens

```go
// Retry on 401 Unauthorized (e.g., for token refresh scenarios)
authRetryChecker := func(err error, resp *http.Response) bool {
    if err != nil {
        return true
    }
    if resp == nil {
        return false
    }
    return resp.StatusCode >= 500 ||
           resp.StatusCode == http.StatusUnauthorized
}

client := retry.NewClient(
    retry.WithRetryableChecker(authRetryChecker),
    retry.WithMaxRetries(3),
)
```

## Testing

Run the test suite:

```bash
go test -v ./internal/retry/
```

With coverage:

```bash
go test -v -cover ./internal/retry/
```

## Design Principles

- **Functional Options Pattern**: Provides clean, flexible API for configuration
- **Sensible Defaults**: Works out of the box for most use cases
- **Context-Aware**: Respects cancellation and timeouts
- **Resource Safe**: Prevents response body leaks by closing them before retries
- **Request Cloning**: Clones requests for each retry to handle consumed request bodies
- **Zero Dependencies**: Uses only standard library

## Migration from Example Code

If you're migrating from `_example/authgate-cli/retry.go`:

**Before:**

```go
resp, err := retryableHTTPRequest(ctx, client, req)
```

**After:**

```go
retryClient := retry.NewClient(
    retry.WithMaxRetries(3),
    retry.WithInitialRetryDelay(1*time.Second),
)
resp, err := retryClient.Do(ctx, req)
```

The behavior is identical, but the new API is more flexible and reusable.
