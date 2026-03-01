package core

import "context"

// AuthResult holds the outcome of an authentication attempt.
type AuthResult struct {
	Username   string
	ExternalID string // External user ID (e.g., LDAP DN, API user ID)
	Email      string // Optional
	FullName   string // Optional
	Success    bool
}

// AuthProvider is the interface that password-based authentication
// backends must implement.
type AuthProvider interface {
	Authenticate(ctx context.Context, username, password string) (*AuthResult, error)
	Name() string
}
