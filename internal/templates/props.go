package templates

import (
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
)

// BaseProps contains common properties shared across all pages
type BaseProps struct {
	CSRFToken string
}

// NavbarProps contains properties for the navigation bar
type NavbarProps struct {
	Username            string
	FullName            string
	IsAdmin             bool
	ActiveLink          string // "device", "sessions", "clients", "audit"
	PendingClientsCount int    // Badge count for admin → OAuth Clients link
}

// DisplayName returns FullName if set, otherwise Username.
func (p *NavbarProps) DisplayName() string {
	if p.FullName != "" {
		return p.FullName
	}
	return p.Username
}

// PaginationProps contains properties for pagination component
type PaginationProps struct {
	Pagination  store.PaginationResult
	BaseURL     string
	QueryParams map[string]string
}

// OAuthProvider represents an OAuth provider configuration
type OAuthProvider struct {
	Name        string
	DisplayName string
}

// ===== Page Props Structures =====

// ErrorPageProps contains properties for the error page
type ErrorPageProps struct {
	BaseProps
	Error   string
	Message string
}

// SuccessPageProps contains properties for the success page
type SuccessPageProps struct {
	BaseProps
	Username   string
	ClientName string
}

// LoginPageProps contains properties for the login page
type LoginPageProps struct {
	BaseProps
	NavbarProps
	Error          string
	Redirect       string
	OAuthProviders []OAuthProvider
}

// DevicePageProps contains properties for the device authorization page
type DevicePageProps struct {
	BaseProps
	NavbarProps
	Username   string
	UserCode   string
	ClientName string
	Error      string
}

// SessionsPageProps contains properties for the sessions page
type SessionsPageProps struct {
	BaseProps
	NavbarProps
	Sessions   []services.TokenWithClient
	Pagination store.PaginationResult
	Search     string
	PageSize   int
}

// ClientsPageProps contains properties for the admin clients page
type ClientsPageProps struct {
	BaseProps
	NavbarProps
	User         *models.User
	Clients      []services.ClientWithCreator
	Pagination   store.PaginationResult
	Search       string
	PageSize     int
	Success      string
	StatusFilter string // "pending", "active", "inactive", or "" for all
}

// ClientDisplay wraps OAuthApplication with string fields for template rendering
type ClientDisplay struct {
	ID                          int64
	ClientID                    string
	ClientName                  string
	Description                 string
	UserID                      string
	Scopes                      string
	GrantTypes                  string
	RedirectURIs                string // Comma-separated string
	ClientType                  string // "confidential" or "public"
	EnableDeviceFlow            bool
	EnableAuthCodeFlow          bool
	EnableClientCredentialsFlow bool
	Status                      string // "pending", "active", "inactive"
	CreatedAt                   time.Time
	UpdatedAt                   time.Time
}

// ClientFormPageProps contains properties for the client form page
type ClientFormPageProps struct {
	BaseProps
	NavbarProps
	Client *ClientDisplay
	Error  string
	IsEdit bool
	Title  string
	Method string
	Action string
}

// ClientCreatedPageProps contains properties for the client created page
type ClientCreatedPageProps struct {
	BaseProps
	NavbarProps
	Client       *ClientDisplay
	ClientSecret string
}

// ClientSecretPageProps contains properties for the client secret page
type ClientSecretPageProps struct {
	BaseProps
	NavbarProps
	Client       *models.OAuthApplication
	ClientSecret string
}

// ClientDetailPageProps contains properties for the client detail page
type ClientDetailPageProps struct {
	BaseProps
	NavbarProps
	Client           *models.OAuthApplication
	ActiveTokenCount int64 // Number of active tokens for this client
	Success          string
	Error            string
}

// AuthorizePageProps contains properties for the OAuth consent page
type AuthorizePageProps struct {
	BaseProps
	NavbarProps
	Username            string
	ClientID            string
	ClientName          string
	ClientDescription   string
	RedirectURI         string
	Scopes              string   // Space-separated scope string
	ScopeList           []string // Pre-split scope list for template iteration
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Error               string
}

// AuthorizationDisplay is a view model for a single user authorization entry
type AuthorizationDisplay struct {
	UUID       string
	ClientID   string
	ClientName string
	Scopes     string
	GrantedAt  time.Time
	IsActive   bool
}

// AuthorizationsPageProps contains properties for the account authorizations page
type AuthorizationsPageProps struct {
	BaseProps
	NavbarProps
	Authorizations []AuthorizationDisplay
	Success        string
	Error          string
}

// ClientAuthorizationDisplay is a view model for one user's grant on the admin overview page
type ClientAuthorizationDisplay struct {
	UUID      string
	UserID    string
	Username  string
	Email     string
	Scopes    string
	GrantedAt time.Time
}

// ClientAuthorizationsPageProps contains properties for the admin client-authorizations page
type ClientAuthorizationsPageProps struct {
	BaseProps
	NavbarProps
	Client         *models.OAuthApplication
	Authorizations []ClientAuthorizationDisplay
	Error          string
}

// DocsEntry represents a single entry in the docs sidebar navigation
type DocsEntry struct {
	Slug     string
	Title    string
	IsActive bool
}

// DocsPageProps contains properties for the docs page
type DocsPageProps struct {
	NavbarProps
	Title       string
	ContentHTML string
	Entries     []DocsEntry
}

// MyAppsPageProps contains properties for the user's own app list page
type MyAppsPageProps struct {
	BaseProps
	NavbarProps
	Apps       []models.OAuthApplication
	Pagination store.PaginationResult
	PageSize   int
	Search     string
}

// UserClientFormPageProps contains properties for the user app create/edit form page
type UserClientFormPageProps struct {
	BaseProps
	NavbarProps
	Title  string
	Action string
	Method string
	IsEdit bool
	Client *ClientDisplay // nil when creating
	Error  string
}

// UserClientDetailPageProps contains properties for the user app detail page
type UserClientDetailPageProps struct {
	BaseProps
	NavbarProps
	Client       *ClientDisplay
	ActiveTokens int64
	Success      string
	Error        string
}

// UserClientCreatedPageProps contains properties for the post-creation page (one-time secret reveal)
type UserClientCreatedPageProps struct {
	BaseProps
	NavbarProps
	Client      *ClientDisplay
	PlainSecret string
}

// ClientFormFieldsProps configures the shared client form fields component.
type ClientFormFieldsProps struct {
	Client                *ClientDisplay
	IsEdit                bool
	NameLabel             string // Display label: "App Name" (user) or "Client Name" (admin)
	ShowClientCredentials bool   // Show Client Credentials Flow checkbox (admin only)
	ScopePresetsOnly      bool   // Restrict scopes to preset chips only (user form)
}

// AuditLogsPageProps contains properties for the audit logs page
type AuditLogsPageProps struct {
	BaseProps
	NavbarProps
	User        *models.User
	Logs        []*models.AuditLog
	TotalItems  int
	Page        int
	TotalPages  int
	NextPage    int
	PrevPage    int
	PageSize    int
	Search      string
	EventType   string
	Severity    string
	Success     string
	ActorIP     string
	QueryString string
}
