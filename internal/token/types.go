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
// internal claims (not in the IANA JWT registry) used by the gateway for
// routing and authorization decisions.
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
