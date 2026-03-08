package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRedirectSafe(t *testing.T) {
	baseURL := "http://localhost:8080"

	tests := []struct {
		name        string
		redirectURL string
		baseURL     string
		want        bool
	}{
		// Valid cases
		{
			name:        "empty redirect is safe",
			redirectURL: "",
			baseURL:     baseURL,
			want:        true,
		},
		{
			name:        "valid relative path",
			redirectURL: "/device",
			baseURL:     baseURL,
			want:        true,
		},
		{
			name:        "valid relative path with query",
			redirectURL: "/device?code=123",
			baseURL:     baseURL,
			want:        true,
		},
		{
			name:        "valid absolute URL with matching host",
			redirectURL: "http://localhost:8080/device",
			baseURL:     baseURL,
			want:        true,
		},
		{
			name:        "valid absolute URL with matching host and https",
			redirectURL: "https://example.com/callback",
			baseURL:     "https://example.com",
			want:        true,
		},

		// Attack vectors - protocol-relative URLs
		{
			name:        "protocol-relative URL to external site",
			redirectURL: "//evil.com",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "protocol-relative URL with path",
			redirectURL: "//evil.com/phishing",
			baseURL:     baseURL,
			want:        false,
		},

		// Attack vectors - absolute URLs to different hosts
		{
			name:        "absolute URL to different host",
			redirectURL: "http://evil.com",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "absolute URL to different host with path",
			redirectURL: "http://evil.com/phishing",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "https URL to different host",
			redirectURL: "https://evil.com",
			baseURL:     baseURL,
			want:        false,
		},

		// Attack vectors - javascript and data URLs
		{
			name:        "javascript URL",
			redirectURL: "javascript:alert('XSS')",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "data URL",
			redirectURL: "data:text/html,<script>alert('XSS')</script>",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "vbscript URL",
			redirectURL: "vbscript:msgbox",
			baseURL:     baseURL,
			want:        false,
		},

		// Attack vectors - backslash tricks
		{
			name:        "backslash in path",
			redirectURL: "/\\evil.com",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "mixed slashes",
			redirectURL: "/\\/evil.com",
			baseURL:     baseURL,
			want:        false,
		},

		// Attack vectors - header injection
		{
			name:        "newline in redirect",
			redirectURL: "/device\nSet-Cookie: evil=true",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "carriage return in redirect",
			redirectURL: "/device\rSet-Cookie: evil=true",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "CRLF in redirect",
			redirectURL: "/device\r\nSet-Cookie: evil=true",
			baseURL:     baseURL,
			want:        false,
		},

		// Edge cases - subdomain attacks
		{
			name:        "subdomain with different host",
			redirectURL: "http://localhost.evil.com",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "port mismatch",
			redirectURL: "http://localhost:9999/device",
			baseURL:     baseURL,
			want:        false,
		},

		// Attack vectors - non-http schemes
		{
			name:        "ftp URL",
			redirectURL: "ftp://evil.com/file",
			baseURL:     baseURL,
			want:        false,
		},
		{
			name:        "file URL",
			redirectURL: "file:///etc/passwd",
			baseURL:     baseURL,
			want:        false,
		},

		// Edge cases - invalid baseURL
		{
			name:        "invalid baseURL with absolute redirect",
			redirectURL: "http://localhost:8080/device",
			baseURL:     "://invalid-url",
			want:        false,
		},

		// Edge cases - invalid redirect URL
		{
			name:        "unparseable redirect URL",
			redirectURL: "http://[::1:bad",
			baseURL:     baseURL,
			want:        false,
		},

		// Valid edge cases
		{
			name:        "path with fragments",
			redirectURL: "/device#section",
			baseURL:     baseURL,
			want:        true,
		},
		{
			name:        "path with encoded characters",
			redirectURL: "/device?redirect=%2Faccount",
			baseURL:     baseURL,
			want:        true,
		},
		{
			name:        "scheme-only URL without host is unsafe",
			redirectURL: "http:",
			baseURL:     baseURL,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRedirectSafe(tt.redirectURL, tt.baseURL)
			assert.Equalf(t, tt.want, got, "IsRedirectSafe(%q, %q)", tt.redirectURL, tt.baseURL)
		})
	}
}
