package util

import "slices"

// AudienceClaim collapses an audience list into the shape conventionally
// emitted as a JWT `aud` claim (RFC 7519 §4.1.3): nil for an empty list,
// a plain string for a single value, or a fresh []string for multiple values.
// The returned slice is a defensive copy so the caller may mutate the input
// without affecting any value already handed to a JWT signer or serializer.
func AudienceClaim(aud []string) any {
	switch len(aud) {
	case 0:
		return nil
	case 1:
		return aud[0]
	default:
		return slices.Clone(aud)
	}
}

// AudienceFromClaims extracts the JWT `aud` claim from a decoded MapClaims
// map and normalizes it to []string. The jwt library decodes single-string
// aud claims as `string` and multi-value aud claims as `[]any` (via
// json.Unmarshal); this helper folds both shapes into the same slice form
// for callers that need the audience without going through the JWT library.
func AudienceFromClaims(claims map[string]any) []string {
	raw, ok := claims["aud"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
