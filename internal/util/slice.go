package util

// IsStringSliceSubset reports whether every element of `sub` appears in
// `super`. An empty `sub` is always a subset; an empty `super` paired with
// a non-empty `sub` is not. Used by RFC 8707 §2.2 audience-narrowing checks
// and any other set-membership test on `[]string` slices.
func IsStringSliceSubset(super, sub []string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(super) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(super))
	for _, v := range super {
		set[v] = struct{}{}
	}
	for _, v := range sub {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}

// IsStringSliceSetEqual reports whether `a` and `b` contain the same set of
// strings (order-independent, duplicates collapsed). Used by RFC 8707 consent
// matching where the resource set the user approved must exactly match the
// set the next request is asking for — narrowing or widening should both
// re-prompt, not silently match a remembered consent.
func IsStringSliceSetEqual(a, b []string) bool {
	return IsStringSliceSubset(a, b) && IsStringSliceSubset(b, a)
}

// UniqueKeys extracts unique non-empty string keys from a slice using keyFn.
func UniqueKeys[T any](items []T, keyFn func(T) string) []string {
	seen := make(map[string]bool, len(items))
	keys := make([]string, 0, len(items))
	for _, item := range items {
		k := keyFn(item)
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}
