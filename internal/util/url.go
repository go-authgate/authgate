package util

import (
	"net/url"
	"strings"
)

// IsRedirectSafe validates that a redirect URL is safe to use.
// It only allows:
// 1. Relative paths starting with "/" but not "//"
// 2. Absolute URLs that match the baseURL host
func IsRedirectSafe(redirectURL, baseURL string) bool {
	// Empty redirect is safe (will use default)
	if redirectURL == "" {
		return true
	}

	// Must not contain newlines or carriage returns (header injection)
	if strings.ContainsAny(redirectURL, "\r\n") {
		return false
	}

	// Check if it's a relative path
	if strings.HasPrefix(redirectURL, "/") {
		// Reject protocol-relative URLs like "//evil.com"
		if strings.HasPrefix(redirectURL, "//") {
			return false
		}
		// Reject backslash variations like "/\evil.com"
		if strings.Contains(redirectURL, "\\") {
			return false
		}
		// Valid relative path
		return true
	}

	// If it's an absolute URL, parse and validate against baseURL
	parsedRedirect, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	// Reject javascript:, data:, and other non-http(s) schemes
	if parsedRedirect.Scheme != "" && parsedRedirect.Scheme != "http" &&
		parsedRedirect.Scheme != "https" {
		return false
	}

	// If there's a host specified, it must match baseURL
	if parsedRedirect.Host != "" {
		parsedBase, err := url.Parse(baseURL)
		if err != nil {
			return false
		}
		// Host must match exactly
		if parsedRedirect.Host != parsedBase.Host {
			return false
		}
	}

	return true
}
