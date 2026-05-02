package token

import (
	"errors"
	"fmt"

	"github.com/go-authgate/authgate/internal/config"
)

// ErrReservedClaimKey is returned when caller-supplied extra claims attempt
// to set a reserved JWT/OIDC standard claim. The issuer owns these claims
// and callers must not provide them via extra_claims.
var ErrReservedClaimKey = errors.New("reserved claim key")

// jwtStripKeys are RFC 7519 registered claims and OIDC ID-token claims that
// AuthGate never sets or preserves on access/refresh tokens — generateJWT
// strips them from extraClaims unconditionally to prevent caller smuggling.
var jwtStripKeys = []string{"nbf", "azp", "amr", "acr", "auth_time", "nonce", "at_hash"}

// computeStripList builds the per-token-provider list of claim keys that
// generateJWT must strip from extraClaims before signing. It includes:
//
//   - jwtStripKeys (RFC 7519 registered + OIDC ID-token keys that have no
//     place in access tokens),
//   - the bare logical names from the private-claim registry (legacy
//     pre-prefix keys: domain / project / service_account),
//   - the default-prefixed forms (extra_domain / extra_project /
//     extra_service_account) WHEN the configured prefix is NOT the default.
//     This blocks an attacker from re-introducing "extra_*" claims on a
//     deployment that has migrated away from the default prefix, where an
//     un-migrated downstream consumer might still hardcode the default.
//     When the configured prefix IS the default, those keys are the
//     legitimate server emission and must NOT be stripped.
//
// Computed once at provider construction so the hot path (every issued
// token) walks a fixed slice without per-call allocation.
func computeStripList(configuredPrefix string) []string {
	out := make([]string, 0, len(jwtStripKeys)+2*len(privateClaims))
	out = append(out, jwtStripKeys...)
	for _, pc := range privateClaims {
		out = append(out, pc.LogicalName)
	}
	if configuredPrefix != config.DefaultJWTPrivateClaimPrefix {
		for _, pc := range privateClaims {
			out = append(out, EmittedName(config.DefaultJWTPrivateClaimPrefix, pc.LogicalName))
		}
	}
	return out
}

// BuildReservedClaimKeys returns the set of JWT claim keys that callers must
// not supply via extra_claims for a deployment configured with the given
// private-claim prefix. It includes:
//
//   - the static RFC/OIDC/AuthGate-internal keys (canonical list owned by
//     internal/config to avoid drift between this package's runtime check
//     and config's startup collision check),
//   - the bare logical names from privateClaims (legacy-name impersonation
//     guard — without it, callers could submit extra_claims={"domain":"evil"}
//     and the bare claim would survive into the signed JWT),
//   - the composed `<prefix>_<logical>` key for every entry in privateClaims,
//   - the default-prefixed forms (extra_<logical>) ALWAYS, regardless of the
//     configured prefix. Reserving the default forms universally blocks an
//     impersonation vector during prefix transitions: a deployment running
//     JWT_PRIVATE_CLAIM_PREFIX=acme would otherwise accept caller-supplied
//     "extra_domain" and let it land in the signed JWT, fooling any
//     un-migrated downstream consumer that still reads the default key.
//
// Build once at parser construction time and reuse — the result is intended
// to be passed into ValidateExtraClaims rather than recomputed per request.
func BuildReservedClaimKeys(prefix string) map[string]struct{} {
	staticKeys := config.StaticReservedClaimKeys()
	out := make(map[string]struct{}, len(staticKeys)+3*len(privateClaims))
	for _, k := range staticKeys {
		out[k] = struct{}{}
	}
	for _, pc := range privateClaims {
		out[pc.LogicalName] = struct{}{}
		out[EmittedName(prefix, pc.LogicalName)] = struct{}{}
		out[EmittedName(config.DefaultJWTPrivateClaimPrefix, pc.LogicalName)] = struct{}{}
	}
	return out
}

// ValidateExtraClaims rejects empty keys and any key in the supplied reserved
// set. Returns the first violation found; nil for an empty or nil claims map.
// The reserved set must be supplied by the caller (typically built once via
// BuildReservedClaimKeys at parser construction time) and must be non-nil —
// a nil reserved map would silently disable reserved-key enforcement
// because nil-map lookups always return ok=false. No additional key-format
// validation (length, character set, namespacing) is performed — callers
// that need stricter input rules must layer them on top.
func ValidateExtraClaims(m map[string]any, reserved map[string]struct{}) error {
	if reserved == nil {
		return errors.New(
			"ValidateExtraClaims: reserved set must be non-nil; " +
				"use BuildReservedClaimKeys to construct it",
		)
	}
	for k := range m {
		if k == "" {
			return fmt.Errorf("%w: empty key", ErrReservedClaimKey)
		}
		if _, ok := reserved[k]; ok {
			return fmt.Errorf("%w: %q", ErrReservedClaimKey, k)
		}
	}
	return nil
}
