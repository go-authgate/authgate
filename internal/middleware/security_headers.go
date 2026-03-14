package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders returns a middleware that sets HTTP security headers
// to protect against common web vulnerabilities. HSTS is only applied
// when useHSTS is true (i.e. when BaseURL uses https://), so local HTTP
// development is unaffected.
func SecurityHeaders(useHSTS bool) gin.HandlerFunc {
	// Build CSP once; the templates use inline scripts/handlers and external CDNs.
	csp := "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'"

	return func(c *gin.Context) {
		h := c.Writer.Header()

		// Prevent MIME-sniffing (e.g. treating uploads as executable scripts)
		h.Set("X-Content-Type-Options", "nosniff")

		// Deny framing to prevent clickjacking on login/consent pages
		h.Set("X-Frame-Options", "DENY")

		// Restrict resource origins to known CDNs used by templates
		h.Set("Content-Security-Policy", csp)

		// Limit cross-origin referrer to origin only, avoiding OAuth parameter leaks
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Restrict browser features that an OAuth server doesn't need
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// Force HTTPS only when the server is actually served over TLS
		if useHSTS {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}
