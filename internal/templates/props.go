package templates

import (
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/services"
	"github.com/go-authgate/authgate/internal/store"
)

// SwaggerEnabled mirrors cfg.SwaggerEnabled. Set once during bootstrap before
// any template renders. Templates read this to hide Swagger UI links when
// the /swagger route is not registered.
var SwaggerEnabled bool

// BaseProps contains common properties shared across all pages
type BaseProps struct {
	CSRFToken string
}

// SfSearchRowProps configures the shared search & filter toolbar search row.
type SfSearchRowProps struct {
	Action          string            // form GET target (e.g. "/account/sessions")
	Search          string            // current search value
	PageSize        int               // current page size
	PageSizeOptions []int             // e.g. [10,20,50]; nil defaults to [10,20,50]
	Placeholder     string            // search input placeholder text
	ClearHref       string            // href for the Clear button
	HiddenFields    map[string]string // extra hidden inputs to preserve filter state
	SearchLabel     string            // submit button text; defaults to "Search"
}

func (p SfSearchRowProps) pageSizeOptions() []int {
	if len(p.PageSizeOptions) > 0 {
		return p.PageSizeOptions
	}
	return []int{10, 20, 50}
}

func (p SfSearchRowProps) searchLabel() string {
	if p.SearchLabel != "" {
		return p.SearchLabel
	}
	return "Search"
}

// NavbarProps contains properties for the navigation bar
type NavbarProps struct {
	Username            string
	FullName            string
	IsAdmin             bool
	ActiveLink          string      // e.g. "device", "sessions", "clients", "audit", "docs-<slug>"
	PendingClientsCount int         // Badge count for admin → OAuth Clients link
	DocsNavEntries      []DocsEntry // Docs dropdown entries, localized per the user's docs_lang cookie
}

// IsDocsActive returns true if the current ActiveLink belongs to a docs page.
func (p *NavbarProps) IsDocsActive() bool {
	return strings.HasPrefix(p.ActiveLink, "docs-")
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
	Error    string
	Message  string
	RetryURL string // URL for the "Try Again" button; defaults to "/" if empty
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
	Error             string
	Redirect          string
	OAuthProviders    []OAuthProvider
	RememberMeEnabled bool
	RememberMeDays    int // Display label: "Remember me for N days"
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
	Sessions       []services.TokenWithClient
	Pagination     store.PaginationResult
	Search         string
	PageSize       int
	StatusFilter   string
	CategoryFilter string
}

// HasActiveFilters returns true if any search or filter is applied.
func (p SessionsPageProps) HasActiveFilters() bool {
	return p.Search != "" || p.StatusFilter != "" || p.CategoryFilter != ""
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
	TokenProfile                string // "short", "standard", or "long"
	Project                     string // Optional; emitted as JWT "project" claim
	ServiceAccount              string // Optional; emitted as JWT "service_account" claim
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

// DocsEntry represents a single entry in the docs sidebar navigation.
// The template derives active-state by comparing Slug to DocsPageProps.CurrentSlug.
type DocsEntry struct {
	Slug  string
	Title string
}

// DocsLocaleOption represents a single choice in the docs language switcher.
// The template derives selected-state by comparing Code to DocsPageProps.Locale
// and builds the HRef from Code and DocsPageProps.CurrentSlug.
type DocsLocaleOption struct {
	Code  string // BCP-47 locale code, e.g. "en", "zh-TW"
	Label string // human-readable label ("English", "繁體中文")
}

// DocsPageProps contains properties for the docs page
type DocsPageProps struct {
	NavbarProps
	Title         string
	ContentHTML   string
	CurrentSlug   string // slug being rendered; drives active/selected state in templ
	Entries       []DocsEntry
	Locale        string // BCP-47 code of the locale used to render this page
	SidebarTitle  string // localized sidebar heading ("Documentation" / "技術文件")
	LangLabel     string // aria-label for the language switcher group
	LocaleOptions []DocsLocaleOption
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

// UserClientSecretPageProps is used by the dedicated secret-regeneration page.
// It carries the same fields as UserClientCreatedPageProps but gives the template
// a self-describing name for the regeneration flow.
type UserClientSecretPageProps = UserClientCreatedPageProps

// SecretRegeneratedCardProps configures the shared secret-regeneration card
// used by both AdminClientSecret and UserAppSecret.
type SecretRegeneratedCardProps struct {
	BreadcrumbItems []BreadcrumbItem
	ClientName      string
	PlainSecret     string
	EditLabel       string // e.g. "Edit Client Settings" or "Edit App Settings"
	EditPath        string
	DetailsPath     string
	BackLabel       string // e.g. "Back to Clients List" or "Back to My Apps"
	BackPath        string
}

// ClientFormFieldsProps configures the shared client form fields component.
type ClientFormFieldsProps struct {
	Client                *ClientDisplay
	IsEdit                bool
	NameLabel             string // Display label: "App Name" (user) or "Client Name" (admin)
	ShowClientCredentials bool   // Render the Client Credentials Flow checkbox; client-type restriction (disabled for public) is enforced in template JS
	ScopePresetsOnly      bool   // Restrict scopes to preset chips only (user form)
}

// UsersPageProps contains properties for the admin users list page
type UsersPageProps struct {
	BaseProps
	NavbarProps
	User             *models.User
	Users            []models.User
	Pagination       store.PaginationResult
	Search           string
	PageSize         int
	Success          string
	RoleFilter       string // "admin", "user", or "" for all
	AuthSourceFilter string // "local", "http_api", or "" for all
}

// UserDetailPageProps contains properties for the admin user detail page
type UserDetailPageProps struct {
	BaseProps
	NavbarProps
	TargetUser           *models.User
	ActiveTokenCount     int64
	OAuthConnectionCount int64
	AuthorizationCount   int64
	Success              string
	Error                string
}

// UserFormPageProps contains properties for the admin user edit form
type UserFormPageProps struct {
	BaseProps
	NavbarProps
	TargetUser *models.User
	Error      string
	IsSelf     bool // true if editing own account (disable role change)
}

// UserPasswordResetPageProps contains properties for the password reset result page
type UserPasswordResetPageProps struct {
	BaseProps
	NavbarProps
	TargetUser  *models.User
	NewPassword string
	Warning     string // non-fatal warning (e.g. token revocation failure)
}

// DashboardPageProps contains properties for the admin dashboard page
type DashboardPageProps struct {
	BaseProps
	NavbarProps
	Stats services.DashboardStats
}

// TokensPageProps contains properties for the admin tokens page
type TokensPageProps struct {
	BaseProps
	NavbarProps
	Tokens         []services.TokenWithUser
	Pagination     store.PaginationResult
	Search         string
	PageSize       int
	StatusFilter   string
	CategoryFilter string
	Success        string
	Warning        string
	Now            time.Time
}

// UserOAuthConnectionsPageProps contains properties for the admin user OAuth connections page
type UserOAuthConnectionsPageProps struct {
	BaseProps
	NavbarProps
	TargetUser  *models.User
	Connections []models.OAuthConnection
	Success     string
	Error       string
}

// UserAuthorizationsPageProps contains properties for the admin user authorizations page
type UserAuthorizationsPageProps struct {
	BaseProps
	NavbarProps
	TargetUser     *models.User
	Authorizations []AuthorizationDisplay
	Success        string
	Error          string
}

// UserCreatePageProps contains properties for the admin user create form
type UserCreatePageProps struct {
	BaseProps
	NavbarProps
	Error    string
	Username string // form repopulation on error
	Email    string
	FullName string
	Role     string
}

// UserCreatedPageProps contains properties for the admin user created success page
type UserCreatedPageProps struct {
	BaseProps
	NavbarProps
	TargetUser  *models.User
	NewPassword string
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
