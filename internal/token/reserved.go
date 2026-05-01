package token

import (
	"errors"
	"fmt"
)

// ErrReservedClaimKey is returned when caller-supplied extra claims attempt
// to set a reserved JWT/OIDC standard claim. The issuer owns these claims
// and callers must not provide them via extra_claims.
var ErrReservedClaimKey = errors.New("reserved claim key")

// reservedClaimKeys lists the JWT/OIDC standard claim keys plus the
// AuthGate-internal claims that callers must not set via extra_claims.
//
// Defence layering:
//  1. Primary — ParseExtraClaims/ValidateExtraClaims reject these keys at the
//     handler edge before the request reaches the token provider.
//  2. Supplementary — generateJWT explicitly overwrites the standard claims it
//     manages (iss/sub/aud/exp/iat/jti/type/scope/user_id/client_id), and
//     drops claims that have no place in an access token: the registered JWT
//     claim nbf and the OIDC ID-token claims (azp/amr/acr/auth_time/nonce/
//     at_hash). This is not a universal override of every entry in this list
//     — AuthGate-internal client metadata claims (project, service_account)
//     are intentionally left alone so the service layer can set them via
//     buildClientClaims.
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

	// Server-attested claim — set from JWT_DOMAIN on every issued token. The
	// service layer overrides any caller-supplied value as a defense in depth,
	// and admins cannot set it per-client either.
	ClaimDomain: {},
}

// IsReservedClaimKey reports whether the given claim key is reserved.
func IsReservedClaimKey(key string) bool {
	_, ok := reservedClaimKeys[key]
	return ok
}

// ValidateExtraClaims rejects empty keys and reserved JWT/OIDC claim keys.
// Returns the first violation found; nil for an empty or nil map. No
// additional key-format validation (length, character set, namespacing) is
// performed — callers that need stricter input rules must layer them on top.
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
