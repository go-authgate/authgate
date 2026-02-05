package templates

import (
	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/store"
)

// BaseProps contains common properties shared across all pages
type BaseProps struct {
	CSRFToken string
}

// NavbarProps contains properties for the navigation bar
type NavbarProps struct {
	Username   string
	IsAdmin    bool
	ActiveLink string // "device", "sessions", "clients", "audit"
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
	User       *models.User
	Clients    []services.ClientWithCreator
	Pagination store.PaginationResult
	Search     string
	PageSize   int
	Success    string
}

// ClientFormPageProps contains properties for the client form page
type ClientFormPageProps struct {
	BaseProps
	NavbarProps
	Client *models.OAuthApplication
	Error  string
	IsEdit bool
}

// ClientCreatedPageProps contains properties for the client created page
type ClientCreatedPageProps struct {
	BaseProps
	NavbarProps
	Client       *models.OAuthApplication
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
	Client  *models.OAuthApplication
	Success string
}

// AuditLogsPageProps contains properties for the audit logs page
type AuditLogsPageProps struct {
	BaseProps
	NavbarProps
	User       *models.User
	Logs       []*models.AuditLog
	TotalItems int
	Page       int
	TotalPages int
	NextPage   int
	PrevPage   int
	PageSize   int
	Search     string
	EventType  string
	Severity   string
	Success    string
	ActorIP    string
}
