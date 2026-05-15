package util

import (
	"errors"
	"net/url"
	"strings"
)

// ErrInvalidResource is returned by ValidateResourceIndicators when a
// `resource` parameter (RFC 8707 §2) is malformed. The handler layer maps
// this to the OAuth error code "invalid_target".
var ErrInvalidResource = errors.New("invalid resource indicator")

// MaxResourceIndicators caps how many `resource` values a single OAuth
// request may carry. RFC 8707 sets no upper bound, so we pick a generous
// limit that defeats DoS amplification (a request could otherwise inflate
// the persisted authorization-code row and the issued JWT's `aud` array).
const MaxResourceIndicators = 10

// MaxResourceURILength caps the length of each individual resource value.
// Without this, a single huge URI would still pass count-validation and
// then balloon DB rows, JWT `aud` arrays, and audit-log payloads. 1024 is
// generous for any realistic MCP server URL.
const MaxResourceURILength = 1024

// ValidateResourceIndicators validates a list of OAuth 2.0 Resource Indicator
// values per RFC 8707 §2.1. Each value must be:
//   - non-empty
//   - within MaxResourceURILength bytes
//   - parseable as a URI
//   - absolute (has a scheme)
//   - http or https scheme — `javascript:`, `data:`, `file:` etc. are
//     rejected so a downstream consumer that turns `aud` back into a URL
//     cannot be tricked into a dangerous scheme
//   - has a non-empty host (rejects shapes like `https:foo` or `http:/path`
//     that pass IsAbs() but have no usable authority)
//   - free of a fragment component
//
// The overall list size is also capped (see MaxResourceIndicators) to
// prevent DoS amplification.
//
// Empty input returns (nil, nil) so callers that don't pass `resource` behave
// exactly as before. On success the caller's slice is returned unchanged —
// the function only validates, it does not transform.
func ValidateResourceIndicators(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > MaxResourceIndicators {
		return nil, ErrInvalidResource
	}
	for _, v := range values {
		if v == "" || len(v) > MaxResourceURILength {
			return nil, ErrInvalidResource
		}
		// Reject any fragment component before parsing — RFC 8707 §2.1 forbids
		// fragments outright, and url.Parse normalizes "https://x/#" to a
		// zero-length Fragment so checking u.Fragment alone misses the empty
		// fragment case. Looking at the raw string for `#` catches both forms.
		if strings.Contains(v, "#") {
			return nil, ErrInvalidResource
		}
		u, err := url.Parse(v)
		if err != nil || !u.IsAbs() {
			return nil, ErrInvalidResource
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return nil, ErrInvalidResource
		}
		// Hostname() strips any port; checking u.Host alone would accept
		// shapes like "https://:443/path" where Host is non-empty (":443")
		// but the actual host is missing — that would let a caller burn an
		// empty-host JWT audience into resource servers' aud checks.
		if u.Hostname() == "" {
			return nil, ErrInvalidResource
		}
	}
	return values, nil
}
