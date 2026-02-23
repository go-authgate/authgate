package auth

// Result represents the result of authentication
type Result struct {
	Username   string
	ExternalID string // External user ID (e.g., LDAP DN, API user ID)
	Email      string // Optional
	FullName   string // Optional
	Success    bool
}
