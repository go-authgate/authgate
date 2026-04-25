package token

import "github.com/go-authgate/authgate/internal/core"

// Token type constants
const (
	TokenTypeBearer = "Bearer"
)

// Token category constants used in the "type" JWT claim.
const (
	TokenCategoryAccess  = "access"
	TokenCategoryRefresh = "refresh"
)

// Custom JWT claim names injected from OAuthApplication metadata. These are
// internal claims (not in the IANA JWT registry).
//
// Note: the claim values are user-supplied (admin or client owner). A signed
// JWT only proves AuthGate emitted these values, not that the named project /
// service account is actually owned by the token holder. Downstream gateways
// that route or authorize on these claims must verify the JWT signature AND
// apply their own access policies — never treat these values as authoritative
// proof of identity. See docs/JWT_VERIFICATION.md for the full trust model.
const (
	ClaimProject        = "project"
	ClaimServiceAccount = "service_account"
)

// Result is an alias for core.TokenResult.
// All existing callers using *token.Result continue to compile unchanged.
type Result = core.TokenResult

// ValidationResult is an alias for core.TokenValidationResult.
type ValidationResult = core.TokenValidationResult

// RefreshResult is an alias for core.TokenRefreshResult.
type RefreshResult = core.TokenRefreshResult
