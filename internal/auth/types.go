package auth

// AuthResult represents the result of authentication
type AuthResult struct {
	Username   string
	ExternalID string // External user ID (e.g., LDAP DN, API user ID)
	Email      string // Optional
	FullName   string // Optional
	Success    bool
}
