package httpclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Authentication mode constants
const (
	AuthModeNone   = "none"   // No authentication
	AuthModeSimple = "simple" // Simple API secret in header
	AuthModeHMAC   = "hmac"   // HMAC-SHA256 signature
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Mode            string // "none", "simple", or "hmac"
	Secret          string // Shared secret key
	HeaderName      string // Custom header name for simple mode (default: "X-API-Secret")
	SignatureHeader string // Signature header name for HMAC mode (default: "X-Signature")
	TimestampHeader string // Timestamp header name for HMAC mode (default: "X-Timestamp")
	NonceHeader     string // Nonce header name for HMAC mode (default: "X-Nonce")
}

// NewAuthConfig creates a new AuthConfig with defaults
func NewAuthConfig(mode, secret string) *AuthConfig {
	return &AuthConfig{
		Mode:            mode,
		Secret:          secret,
		HeaderName:      "X-API-Secret",
		SignatureHeader: "X-Signature",
		TimestampHeader: "X-Timestamp",
		NonceHeader:     "X-Nonce",
	}
}

// AddAuthHeaders adds authentication headers to the HTTP request based on configured mode
func (c *AuthConfig) AddAuthHeaders(req *http.Request, body []byte) error {
	if c == nil || c.Mode == AuthModeNone || c.Mode == "" {
		return nil // No authentication
	}

	switch c.Mode {
	case AuthModeSimple:
		return c.addSimpleAuth(req)
	case AuthModeHMAC:
		return c.addHMACAuth(req, body)
	default:
		return fmt.Errorf("unsupported authentication mode: %s", c.Mode)
	}
}

// addSimpleAuth adds simple API secret header
func (c *AuthConfig) addSimpleAuth(req *http.Request) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for simple authentication")
	}

	headerName := c.HeaderName
	if headerName == "" {
		headerName = "X-API-Secret"
	}

	req.Header.Set(headerName, c.Secret)
	return nil
}

// addHMACAuth adds HMAC signature headers
func (c *AuthConfig) addHMACAuth(req *http.Request, body []byte) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for HMAC authentication")
	}

	// Generate timestamp and nonce
	timestamp := time.Now().Unix()
	nonce := uuid.New().String()

	// Calculate signature: HMAC-SHA256(secret, timestamp + method + path + query + body)
	signature := c.calculateHMACSignature(
		timestamp,
		req.Method,
		getFullPath(req),
		body,
	)

	// Set headers
	signatureHeader := c.SignatureHeader
	if signatureHeader == "" {
		signatureHeader = "X-Signature"
	}

	timestampHeader := c.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = "X-Timestamp"
	}

	nonceHeader := c.NonceHeader
	if nonceHeader == "" {
		nonceHeader = "X-Nonce"
	}

	req.Header.Set(signatureHeader, signature)
	req.Header.Set(timestampHeader, strconv.FormatInt(timestamp, 10))
	req.Header.Set(nonceHeader, nonce)

	return nil
}

// calculateHMACSignature calculates HMAC-SHA256 signature
func (c *AuthConfig) calculateHMACSignature(
	timestamp int64,
	method, path string,
	body []byte,
) string {
	// Create message: timestamp + method + path + body
	message := fmt.Sprintf("%d%s%s%s",
		timestamp,
		method,
		path,
		string(body),
	)

	// Calculate HMAC-SHA256
	h := hmac.New(sha256.New, []byte(c.Secret))
	h.Write([]byte(message))

	return hex.EncodeToString(h.Sum(nil))
}

// getFullPath returns the full request path including query parameters
func getFullPath(req *http.Request) string {
	path := req.URL.Path
	if req.URL.RawQuery != "" {
		return path + "?" + req.URL.RawQuery
	}
	return path
}

// VerifyHMACSignature verifies HMAC signature from request (for server-side validation)
func (c *AuthConfig) VerifyHMACSignature(req *http.Request, maxAge time.Duration) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for HMAC verification")
	}

	// Get headers
	signatureHeader := c.SignatureHeader
	if signatureHeader == "" {
		signatureHeader = "X-Signature"
	}

	timestampHeader := c.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = "X-Timestamp"
	}

	signature := req.Header.Get(signatureHeader)
	timestampStr := req.Header.Get(timestampHeader)

	if signature == "" || timestampStr == "" {
		return fmt.Errorf("missing authentication headers")
	}

	// Parse timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	// Check timestamp age (default: 5 minutes)
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}

	requestTime := time.Unix(timestamp, 0)
	if time.Since(requestTime) > maxAge {
		return fmt.Errorf("request timestamp expired")
	}

	// Read body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	// Restore body for subsequent handlers
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	// Calculate expected signature (including query parameters)
	expectedSignature := c.calculateHMACSignature(
		timestamp,
		req.Method,
		getFullPath(req),
		body,
	)

	// Compare signatures
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
