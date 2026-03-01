package auth

import "github.com/go-authgate/authgate/internal/core"

// Result is a type alias for core.AuthResult.
// Using an alias (not a new type) keeps all existing *auth.Result references
// valid without any changes at call sites.
type Result = core.AuthResult
