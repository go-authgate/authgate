package token

import (
	"errors"
	"fmt"
)

// ErrReservedClaimKey is returned when caller-supplied extra claims attempt
// to set a reserved JWT/OIDC standard claim. The issuer owns these claims;
// generateJWT also overrides them after the extra-claims merge as a
// second-line defence.
var ErrReservedClaimKey = errors.New("reserved claim key")

// reservedClaimKeys lists the JWT/OIDC standard claim keys plus the
// AuthGate-internal claims that callers must not set via extra_claims.
//
// Two-layer defence:
//  1. ParseExtraClaims rejects requests at the handler edge.
//  2. generateJWT writes standard claims after the extra-claims merge, so
//     even if a key slips past validation, the issuer's value wins.
var reservedClaimKeys = map[string]struct{}{
	// RFC 7519 §4.1 registered claim names
	"iss": {},
	"sub": {},
	"aud": {},
	"exp": {},
	"nbf": {},
	"iat": {},
	"jti": {},

	// AuthGate-internal claims set unconditionally by generateJWT
	"type":      {},
	"scope":     {},
	"user_id":   {},
	"client_id": {},

	// OIDC ID token standard claims (OIDC Core 1.0 §2)
	"azp":       {},
	"amr":       {},
	"acr":       {},
	"auth_time": {},
	"nonce":     {},
	"at_hash":   {},

	// AuthGate-internal client metadata claims — owned by the OAuthApplication
	// row, callers cannot impersonate them via extra_claims.
	ClaimProject:        {},
	ClaimServiceAccount: {},
}

// IsReservedClaimKey reports whether the given claim key is reserved.
func IsReservedClaimKey(key string) bool {
	_, ok := reservedClaimKeys[key]
	return ok
}

// ValidateExtraClaims rejects empty keys and reserved JWT/OIDC claim keys.
// Returns the first violation; nil for an empty or nil map.
func ValidateExtraClaims(m map[string]any) error {
	for k := range m {
		if k == "" {
			return fmt.Errorf("%w: empty key", ErrReservedClaimKey)
		}
		if IsReservedClaimKey(k) {
			return fmt.Errorf("%w: %q", ErrReservedClaimKey, k)
		}
	}
	return nil
}
