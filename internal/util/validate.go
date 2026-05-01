package util

import "regexp"

// projectIdentifierPattern is the canonical identifier shape shared by the
// per-client `project` claim and the server-wide `domain` claim from
// JWT_DOMAIN: 1–64 chars of [A-Za-z0-9_.-], starting and ending with an
// alphanumeric. The alternation admits the single-character case.
var projectIdentifierPattern = regexp.MustCompile(
	`^[a-zA-Z0-9]$|^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}[a-zA-Z0-9]$`,
)

// IsValidProjectIdentifier reports whether s matches the project-identifier
// shape. Empty input returns false; callers that treat empty as "unset" must
// check before calling.
func IsValidProjectIdentifier(s string) bool {
	return projectIdentifierPattern.MatchString(s)
}
