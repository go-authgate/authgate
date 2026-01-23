package retry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()

	if client.maxRetries != defaultMaxRetries {
		t.Errorf("expected maxRetries=%d, got %d", defaultMaxRetries, client.maxRetries)
	}
	if client.initialRetryDelay != defaultInitialRetryDelay {
		t.Errorf(
			"expected initialRetryDelay=%v, got %v",
			defaultInitialRetryDelay,
			client.initialRetryDelay,
		)
	}
	if client.maxRetryDelay != defaultMaxRetryDelay {
		t.Errorf("expected maxRetryDelay=%v, got %v", defaultMaxRetryDelay, client.maxRetryDelay)
	}
	if client.retryDelayMultiple != defaultRetryDelayMultiple {
		t.Errorf(
			"expected retryDelayMultiple=%f, got %f",
			defaultRetryDelayMultiple,
			client.retryDelayMultiple,
		)
	}
	if client.httpClient == nil {
		t.Error("expected httpClient to be set")
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	customChecker := func(err error, resp *http.Response) bool { return false }

	client := NewClient(
		WithMaxRetries(5),
		WithInitialRetryDelay(2*time.Second),
		WithMaxRetryDelay(20*time.Second),
		WithRetryDelayMultiple(3.0),
		WithHTTPClient(httpClient),
		WithRetryableChecker(customChecker),
	)

	if client.maxRetries != 5 {
		t.Errorf("expected maxRetries=5, got %d", client.maxRetries)
	}
	if client.initialRetryDelay != 2*time.Second {
		t.Errorf("expected initialRetryDelay=2s, got %v", client.initialRetryDelay)
	}
	if client.maxRetryDelay != 20*time.Second {
		t.Errorf("expected maxRetryDelay=20s, got %v", client.maxRetryDelay)
	}
	if client.retryDelayMultiple != 3.0 {
		t.Errorf("expected retryDelayMultiple=3.0, got %f", client.retryDelayMultiple)
	}
	if client.httpClient != httpClient {
		t.Error("expected custom httpClient to be set")
	}
}

func TestNewClient_InvalidOptions(t *testing.T) {
	client := NewClient(
		WithMaxRetries(-1),          // Invalid, should be ignored
		WithInitialRetryDelay(-1),   // Invalid, should be ignored
		WithMaxRetryDelay(-1),       // Invalid, should be ignored
		WithRetryDelayMultiple(0.5), // Invalid, should be ignored
	)

	// Should still have defaults
	if client.maxRetries != defaultMaxRetries {
		t.Errorf("expected default maxRetries=%d, got %d", defaultMaxRetries, client.maxRetries)
	}
	if client.initialRetryDelay != defaultInitialRetryDelay {
		t.Errorf(
			"expected default initialRetryDelay=%v, got %v",
			defaultInitialRetryDelay,
			client.initialRetryDelay,
		)
	}
}

func TestDefaultRetryableChecker(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		resp     *http.Response
		expected bool
	}{
		{
			name:     "network error",
			err:      errors.New("connection refused"),
			resp:     nil,
			expected: true,
		},
		{
			name:     "no error, 200 OK",
			err:      nil,
			resp:     &http.Response{StatusCode: http.StatusOK},
			expected: false,
		},
		{
			name:     "no error, 400 Bad Request",
			err:      nil,
			resp:     &http.Response{StatusCode: http.StatusBadRequest},
			expected: false,
		},
		{
			name:     "no error, 429 Too Many Requests",
			err:      nil,
			resp:     &http.Response{StatusCode: http.StatusTooManyRequests},
			expected: true,
		},
		{
			name:     "no error, 500 Internal Server Error",
			err:      nil,
			resp:     &http.Response{StatusCode: http.StatusInternalServerError},
			expected: true,
		},
		{
			name:     "no error, 503 Service Unavailable",
			err:      nil,
			resp:     &http.Response{StatusCode: http.StatusServiceUnavailable},
			expected: true,
		},
		{
			name:     "no error, nil response",
			err:      nil,
			resp:     nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DefaultRetryableChecker(tt.err, tt.resp)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestClient_Do_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	client := NewClient(
		WithInitialRetryDelay(10*time.Millisecond),
		WithMaxRetries(2),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestClient_Do_RetryOn500(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success after retries"))
	}))
	defer server.Close()

	client := NewClient(
		WithInitialRetryDelay(10*time.Millisecond),
		WithMaxRetries(3),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestClient_Do_ExhaustedRetries(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithInitialRetryDelay(10*time.Millisecond),
		WithMaxRetries(2),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should return the last response with 500 status
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}

	// Should have 1 initial attempt + 2 retries = 3 total
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestClient_Do_ContextCancellation(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithInitialRetryDelay(100*time.Millisecond),
		WithMaxRetries(5),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(ctx, req)
	if err == nil {
		defer resp.Body.Close()
		t.Fatal("expected context cancellation error")
	}

	// Should only have 1 attempt before context is cancelled during retry delay
	if attempts.Load() > 2 {
		t.Errorf("expected at most 2 attempts before cancellation, got %d", attempts.Load())
	}
}

func TestClient_Do_NoRetryOn4xx(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := NewClient(
		WithInitialRetryDelay(10*time.Millisecond),
		WithMaxRetries(3),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should not retry on 4xx errors
	if attempts.Load() != 1 {
		t.Errorf("expected 1 attempt (no retries), got %d", attempts.Load())
	}
}

func TestClient_Do_ExponentialBackoff(t *testing.T) {
	var attempts atomic.Int32
	var requestTimes []time.Time

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(
		WithInitialRetryDelay(100*time.Millisecond),
		WithMaxRetryDelay(500*time.Millisecond),
		WithRetryDelayMultiple(2.0),
		WithMaxRetries(3),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(ctx, req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}

	if len(requestTimes) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(requestTimes))
	}

	// Check that delays increase exponentially
	delay1 := requestTimes[1].Sub(requestTimes[0])
	delay2 := requestTimes[2].Sub(requestTimes[1])

	if delay1 < 90*time.Millisecond || delay1 > 150*time.Millisecond {
		t.Errorf("first retry delay should be ~100ms, got %v", delay1)
	}

	if delay2 < 180*time.Millisecond || delay2 > 250*time.Millisecond {
		t.Errorf("second retry delay should be ~200ms, got %v", delay2)
	}
}

func TestClient_Do_CustomRetryableChecker(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Custom checker that never retries
	neverRetry := func(err error, resp *http.Response) bool {
		return false
	}

	client := NewClient(
		WithInitialRetryDelay(10*time.Millisecond),
		WithMaxRetries(3),
		WithRetryableChecker(neverRetry),
	)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should not retry with custom checker
	if attempts.Load() != 1 {
		t.Errorf("expected 1 attempt (no retries), got %d", attempts.Load())
	}
}
