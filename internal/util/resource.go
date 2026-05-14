package util

import (
	"errors"
	"net/url"
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

// ValidateResourceIndicators validates a list of OAuth 2.0 Resource Indicator
// values per RFC 8707 §2.1. Each value must be:
//   - non-empty
//   - parseable as a URI
//   - absolute (has a scheme)
//   - http or https scheme — `javascript:`, `data:`, `file:` etc. are
//     rejected so a downstream consumer that turns `aud` back into a URL
//     cannot be tricked into a dangerous scheme
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
		if v == "" {
			return nil, ErrInvalidResource
		}
		u, err := url.Parse(v)
		if err != nil || !u.IsAbs() || u.Fragment != "" {
			return nil, ErrInvalidResource
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return nil, ErrInvalidResource
		}
	}
	return values, nil
}
