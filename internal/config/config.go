package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/joho/godotenv"
)

// Authentication mode constants
const (
	AuthModeLocal   = "local"
	AuthModeHTTPAPI = "http_api"
)

// Rate limit store constants
const (
	RateLimitStoreMemory = "memory"
	RateLimitStoreRedis  = "redis"
)

// CacheType constants shared by metrics, user, and client count caches.
const (
	CacheTypeMemory     = "memory"
	CacheTypeRedis      = "redis"
	CacheTypeRedisAside = "redis-aside"
)

// JWT signing algorithm constants.
const (
	AlgHS256 = "HS256"
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// DefaultJWTPrivateClaimPrefix is the namespace token AuthGate prepends to
// every AuthGate-emitted private JWT claim when JWT_PRIVATE_CLAIM_PREFIX is
// unset. Composed keys: extra_domain, extra_project, extra_service_account.
const DefaultJWTPrivateClaimPrefix = "extra"

// jwtPrivateClaimPrefixPattern is the canonical shape for the configurable
// private-claim prefix: starts with a letter, then letters/digits/underscores.
// Length is bounded separately (1–15). A trailing underscore is rejected
// separately because AuthGate adds the separating underscore itself —
// disallowing one in the configured value prevents accidental "extra__domain".
var jwtPrivateClaimPrefixPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

// jwtPrivateClaimPrefixMaxLen is the upper bound on the configured prefix.
// 15 keeps `<prefix>_<longest-logical-name>` well under practical JWT key-size
// limits (e.g. extra_service_account is 21 chars, acme_service_account is 20).
const jwtPrivateClaimPrefixMaxLen = 15

// staticReservedClaimKeys is the canonical static set of claim keys
// (RFC 7519 §4.1 registered claims, OIDC Core 1.0 §2 ID-token claims, and
// AuthGate-internal claims set unconditionally by token.generateJWT) that
// callers must never set via extra_claims and that the configured
// JWT_PRIVATE_CLAIM_PREFIX's composed keys must not collide with.
//
// Owned here (in the leaf-most package between config and token: config
// is imported by token, not the other way around) so internal/token can
// reuse it for runtime reserved-key derivation rather than maintaining a
// drift-prone parallel list.
//
// Unexported so other packages cannot accidentally append/mutate the slice
// at runtime — that would silently change reserved-claim enforcement and
// the prefix collision validation. External callers must go through
// StaticReservedClaimKeys() which returns a defensive copy.
var staticReservedClaimKeys = []string{
	// RFC 7519 §4.1
	"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
	// AuthGate-internal claims set unconditionally by generateJWT
	"type", "scope", "user_id", "client_id",
	// OIDC Core 1.0 §2 (ID token)
	"azp", "amr", "acr", "auth_time", "nonce", "at_hash",
}

// StaticReservedClaimKeys returns a defensive copy of the canonical static
// reserved-claim list (see staticReservedClaimKeys). The underlying slice
// is intentionally unexported to prevent cross-package mutation; callers
// that need to iterate must use this accessor.
func StaticReservedClaimKeys() []string {
	out := make([]string, len(staticReservedClaimKeys))
	copy(out, staticReservedClaimKeys)
	return out
}

// jwtPrivateClaimLogicalNames mirrors the logical names of the registry in
// internal/token/types.go (the unexported privateClaims slice, exposed via
// token.PrivateClaimRegistry()). Replicated here only for the startup
// collision check; the canonical registry lives in the token package.
// A cross-package drift guard test (TestPrivateClaimRegistryDrift in
// internal/config/drift_test.go) fails the build if these diverge.
var jwtPrivateClaimLogicalNames = []string{
	"domain",
	"project",
	"service_account",
	"uid",
}

// PrivateClaimLogicalNames returns a defensive copy of the local
// jwtPrivateClaimLogicalNames slice. Exported solely for the cross-package
// drift guard test that compares this list against token.PrivateClaimRegistry().
func PrivateClaimLogicalNames() []string {
	out := make([]string, len(jwtPrivateClaimLogicalNames))
	copy(out, jwtPrivateClaimLogicalNames)
	return out
}

// TokenProfile defines the access and refresh token lifetimes for a named preset.
// Clients reference a profile by name via OAuthApplication.TokenProfile (see
// models.TokenProfile* constants) and the TTL is resolved at token issuance.
type TokenProfile struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

type Config struct {
	// Server settings
	ServerAddr  string
	BaseURL     string
	TLSCertFile string // Both TLSCertFile and TLSKeyFile must be set to serve HTTPS.
	TLSKeyFile  string

	// Environment detection
	IsProduction bool

	// Decoupled from IsProduction so prod deployments can opt in behind internal networking.
	SwaggerEnabled bool

	// JWT settings
	JWTSecret           string
	JWTExpiration       time.Duration
	JWTSigningAlgorithm string        // "HS256" (default), "RS256", or "ES256"
	JWTPrivateKeyPath   string        // PEM file path (required for RS256/ES256 when PEM content is not set)
	JWTPrivateKeyPEM    string        // PEM content (alternative to JWTPrivateKeyPath; takes precedence if both are set)
	JWTKeyID            string        // "kid" header for JWKS key rotation (auto-generated if empty)
	JWTExpirationJitter time.Duration // Max random jitter added to access token expiry (default: 30m)
	JWTAudience         []string      // "aud" claim values for issued access/refresh tokens (comma-separated env). Single entry → string, multiple → array. Empty → claim omitted.
	JWTDomain           string        // Server-attested domain value emitted as "<prefix>_domain" (default: "extra_domain") on every issued JWT. Empty → claim omitted (default). Validated at startup via util.IsValidProjectIdentifier.
	// JWTPrivateClaimPrefix is the namespace token AuthGate prepends (with an
	// underscore separator AuthGate adds itself) to every AuthGate-emitted
	// private JWT claim. With the default "extra", JWTs carry "extra_domain",
	// "extra_project", "extra_service_account". An empty value is treated as
	// "use the default" — Validate() checks it against the default without
	// mutating this field; runtime callers (NewLocalTokenProvider,
	// NewExtraClaimsParser, TokenService) each normalize empty → default
	// locally. Validated at startup: must match ^[a-zA-Z][a-zA-Z0-9_]*$,
	// 1–15 chars, no trailing underscore, and none of the composed
	// "<prefix>_<logical>" keys may collide with any RFC 7519 / OIDC /
	// AuthGate-internal claim key.
	JWTPrivateClaimPrefix string

	// Session settings
	SessionSecret            string
	SessionMaxAge            int  // Session max age in seconds (default: 3600 = 1 hour)
	SessionIdleTimeout       int  // Session idle timeout in seconds (0 = disabled, default: 1800 = 30 minutes)
	SessionFingerprint       bool // Enable session fingerprinting (IP + User-Agent validation, default: true)
	SessionFingerprintIP     bool // Include IP address in fingerprint (default: false, due to dynamic IPs)
	SessionRememberMeEnabled bool // Enable "Remember Me" checkbox on login (default: true)
	SessionRememberMeMaxAge  int  // Remember Me session max age in seconds (default: 2592000 = 30 days)

	// Device code settings
	DeviceCodeExpiration time.Duration
	PollingInterval      int // seconds

	// Database
	DatabaseDriver string // "sqlite" or "postgres"
	DatabaseDSN    string // Database connection string (DSN or path)

	// Database connection pool settings
	DBMaxOpenConns    int           // Maximum number of open connections (default: 25)
	DBMaxIdleConns    int           // Maximum number of idle connections (default: 10)
	DBConnMaxLifetime time.Duration // Maximum connection lifetime (default: 5 minutes)
	DBConnMaxIdleTime time.Duration // Maximum connection idle time (default: 10 minutes)
	DBLogLevel        string        // GORM log level: "silent", "error", "warn", "info" (default: "warn")

	// Default Admin User
	DefaultAdminPassword string // Default admin password (if empty, random password is generated)

	// Authentication
	AuthMode string // "local" or "http_api"

	// HTTP API Authentication
	HTTPAPIURL                string
	HTTPAPITimeout            time.Duration
	HTTPAPIInsecureSkipVerify bool
	HTTPAPIAuthMode           string // Authentication mode: "none", "simple", or "hmac"
	HTTPAPIAuthSecret         string // Shared secret for authentication
	HTTPAPIAuthHeader         string // Custom header name for simple mode (default: "X-API-Secret")
	HTTPAPIMaxRetries         int    // Maximum retry attempts (default: 3)
	HTTPAPIRetryDelay         time.Duration
	HTTPAPIMaxRetryDelay      time.Duration

	// Refresh Token settings
	RefreshTokenExpiration time.Duration // Refresh token lifetime (default: 720h = 30 days)
	EnableRefreshTokens    bool          // Feature flag to enable/disable refresh tokens (default: true)
	EnableTokenRotation    bool          // Enable token rotation mode (default: false, fixed mode)

	// Token lifetime hard caps. Any TokenProfile value that exceeds these is rejected
	// during Validate(). Prevents a misconfigured profile from silently extending token
	// lifetime far beyond the security intent.
	JWTExpirationMax          time.Duration // env: JWT_EXPIRATION_MAX (default: 24h)
	RefreshTokenExpirationMax time.Duration // env: REFRESH_TOKEN_EXPIRATION_MAX (default: 2160h / 90d)

	// TokenProfiles maps a profile name ("short" / "standard" / "long") to its TTLs.
	// Populated in Load() from the TOKEN_PROFILE_*_ACCESS_TTL / TOKEN_PROFILE_*_REFRESH_TTL env
	// vars; the "standard" profile falls back to JWTExpiration / RefreshTokenExpiration.
	TokenProfiles map[string]TokenProfile

	// Client Credentials Flow settings (RFC 6749 §4.4)
	ClientCredentialsTokenExpiration time.Duration // Access token lifetime for client_credentials grant (default: 1h, same as JWTExpiration)

	// Caller-supplied JWT extra claims (extra_claims parameter on /oauth/token).
	// Enabled by default. Reserved JWT/OIDC keys are always rejected regardless
	// of these limits. Custom claims are NOT persisted, so callers must
	// re-supply extra_claims on every refresh to retain them.
	ExtraClaimsEnabled    bool // EXTRA_CLAIMS_ENABLED (default: true)
	ExtraClaimsMaxRawSize int  // EXTRA_CLAIMS_MAX_RAW_SIZE in bytes (default: 4096; 0 disables the check)
	ExtraClaimsMaxKeys    int  // EXTRA_CLAIMS_MAX_KEYS (default: 16; 0 disables the check)
	ExtraClaimsMaxValSize int  // EXTRA_CLAIMS_MAX_VAL_SIZE in bytes per value (default: 512; 0 disables the check)

	// OAuth settings
	// GitHub OAuth
	GitHubOAuthEnabled     bool
	GitHubClientID         string
	GitHubClientSecret     string
	GitHubOAuthRedirectURL string
	GitHubOAuthScopes      []string

	// Gitea OAuth
	GiteaOAuthEnabled     bool
	GiteaURL              string
	GiteaClientID         string
	GiteaClientSecret     string
	GiteaOAuthRedirectURL string
	GiteaOAuthScopes      []string

	// Microsoft Entra ID OAuth
	MicrosoftOAuthEnabled     bool
	MicrosoftTenantID         string // "common", "organizations", or tenant UUID
	MicrosoftClientID         string
	MicrosoftClientSecret     string
	MicrosoftOAuthRedirectURL string
	MicrosoftOAuthScopes      []string

	// GitLab OAuth
	GitLabOAuthEnabled     bool
	GitLabURL              string // Base URL; defaults to "https://gitlab.com" for cloud
	GitLabClientID         string
	GitLabClientSecret     string
	GitLabOAuthRedirectURL string
	GitLabOAuthScopes      []string

	// OAuth Auto Registration
	OAuthAutoRegister bool // Allow OAuth to auto-create accounts (default: true)

	// OAuth HTTP Client Settings
	OAuthTimeout            time.Duration // HTTP client timeout for OAuth requests (default: 15s)
	OAuthInsecureSkipVerify bool          // Skip TLS verification for OAuth (dev/testing only, default: false)

	// Rate Limiting settings
	EnableRateLimit          bool   // Enable rate limiting (default: true)
	RateLimitStore           string // Rate limit store: "memory" or "redis" (default: "memory")
	RateLimitCleanupInterval time.Duration
	LoginRateLimit           int // Requests per minute for /login endpoint (default: 5)
	DeviceCodeRateLimit      int // Requests per minute for /oauth/device/code (default: 10)
	TokenRateLimit           int // Requests per minute for /oauth/token (default: 20)
	DeviceVerifyRateLimit    int // Requests per minute for /device/verify (default: 10)
	IntrospectRateLimit      int // Requests per minute for /oauth/introspect (default: 20)

	// Redis settings (only used when RateLimitStore = "redis")
	RedisAddr     string // Redis address for rate limiting (e.g., "localhost:6379")
	RedisPassword string // Redis password (empty for no auth)
	RedisDB       int    // Redis database number (default: 0)

	// Audit Logging settings
	EnableAuditLogging      bool          // Enable audit logging (default: true)
	AuditLogRetention       time.Duration // Retention period for audit logs (default: 90 days)
	AuditLogBufferSize      int           // Async buffer size (default: 1000)
	AuditLogCleanupInterval time.Duration // Cleanup interval (default: 24 hours)

	// Token/Device Code cleanup settings
	EnableExpiredTokenCleanup   bool          // Enable periodic cleanup of expired tokens and device codes (default: false)
	ExpiredTokenCleanupInterval time.Duration // How often to purge expired rows (default: 1h)

	// Prometheus Metrics settings
	MetricsEnabled             bool          // Enable Prometheus metrics endpoint (default: false)
	MetricsToken               string        // Bearer token for /metrics (empty = no auth, recommended for production)
	MetricsGaugeUpdateEnabled  bool          // Enable gauge metric updates (default: true, disable on all but one replica)
	MetricsGaugeUpdateInterval time.Duration // Gauge update interval (default: 5m)
	MetricsCacheType           string        // Cache backend: memory, redis, redis-aside (default: memory)
	MetricsCacheClientTTL      time.Duration // Client-side cache TTL for redis-aside (default: 30s)
	MetricsCacheSizePerConn    int           // Client-side cache size per connection in MB for redis-aside (default: 32MB)

	// User Cache settings
	UserCacheType        string        // USER_CACHE_TYPE: memory|redis|redis-aside (default: memory)
	UserCacheTTL         time.Duration // USER_CACHE_TTL (default: 5m)
	UserCacheClientTTL   time.Duration // USER_CACHE_CLIENT_TTL for redis-aside client-side TTL (default: 30s)
	UserCacheSizePerConn int           // USER_CACHE_SIZE_PER_CONN: client-side cache size per connection in MB for redis-aside (default: 32MB)

	// Client Count Cache settings (pending badge in admin navbar)
	ClientCountCacheType        string        // CLIENT_COUNT_CACHE_TYPE: memory|redis|redis-aside (default: memory)
	ClientCountCacheTTL         time.Duration // CLIENT_COUNT_CACHE_TTL: server-side cache lifetime (default: 1h)
	ClientCountCacheClientTTL   time.Duration // CLIENT_COUNT_CACHE_CLIENT_TTL for redis-aside (default: 10m)
	ClientCountCacheSizePerConn int           // CLIENT_COUNT_CACHE_SIZE_PER_CONN for redis-aside in MB (default: 32MB)

	// Client Cache settings (caches OAuth client lookups by client_id)
	ClientCacheType        string        // CLIENT_CACHE_TYPE: memory|redis|redis-aside (default: memory)
	ClientCacheTTL         time.Duration // CLIENT_CACHE_TTL: cache lifetime (default: 5m)
	ClientCacheClientTTL   time.Duration // CLIENT_CACHE_CLIENT_TTL for redis-aside client-side TTL (default: 30s)
	ClientCacheSizePerConn int           // CLIENT_CACHE_SIZE_PER_CONN: client-side cache size per connection in MB for redis-aside (default: 32MB)

	// Token Cache settings (reduces DB queries for token verification)
	TokenCacheEnabled     bool          // TOKEN_CACHE_ENABLED: enable token verification cache (default: false)
	TokenCacheType        string        // TOKEN_CACHE_TYPE: memory|redis|redis-aside (default: memory)
	TokenCacheTTL         time.Duration // TOKEN_CACHE_TTL: cache lifetime (default: 10h, matches JWT_EXPIRATION)
	TokenCacheClientTTL   time.Duration // TOKEN_CACHE_CLIENT_TTL: redis-aside client-side TTL (default: 1h)
	TokenCacheSizePerConn int           // TOKEN_CACHE_SIZE_PER_CONN: redis-aside size in MB (default: 32MB)

	// Dynamic Client Registration (RFC 7591)
	EnableDynamicClientRegistration    bool   // Enable POST /oauth/register endpoint (default: false)
	DynamicClientRegistrationRateLimit int    // Requests per minute for /oauth/register (default: 5)
	DynamicClientRegistrationToken     string // Initial access token for protected registration (empty = open registration)

	// Authorization Code Flow settings (RFC 6749)
	AuthCodeExpiration time.Duration // Authorization code lifetime (default: 10 minutes)
	PKCERequired       bool          // Force PKCE for all public clients (default: false)
	ConsentRemember    bool          // Skip consent page if user already authorized same scope (default: true)

	// CORS settings
	CORSEnabled        bool          // Enable CORS for API endpoints (default: false)
	CORSAllowedOrigins []string      // Allowed origins (comma-separated via env, e.g. "http://localhost:3000")
	CORSAllowedMethods []string      // Allowed HTTP methods (default: GET,POST,PUT,DELETE,OPTIONS)
	CORSAllowedHeaders []string      // Allowed request headers (default: Origin,Content-Type,Authorization)
	CORSMaxAge         time.Duration // Preflight cache duration (default: 12 hours)

	// Static file caching
	StaticCacheMaxAge time.Duration // Cache-Control max-age for non-hashed static files (default: 24h, 0 disables)

	// Bootstrap and shutdown timeout settings
	DBInitTimeout         time.Duration // Database initialization timeout (default: 30s)
	RedisConnTimeout      time.Duration // Redis connection timeout (default: 5s)
	CacheInitTimeout      time.Duration // Cache initialization timeout (default: 5s)
	ServerShutdownTimeout time.Duration // HTTP server graceful shutdown timeout (default: 5s)
	AuditShutdownTimeout  time.Duration // Audit service shutdown timeout (default: 10s)
	RedisCloseTimeout     time.Duration // Redis close timeout (default: 5s)
	CacheCloseTimeout     time.Duration // Cache close timeout (default: 5s)
	DBCloseTimeout        time.Duration // Database close timeout (default: 5s)
}

// TLSEnabled reports whether TLS serving should be activated.
// Both TLSCertFile and TLSKeyFile must be set for TLS to be enabled.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func Load() *Config {
	// Load .env file if exists (ignore error if not found)
	_ = godotenv.Load()

	// Determine database driver and DSN
	driver := getEnv("DATABASE_DRIVER", "sqlite")
	var dsn string
	if driver == "sqlite" {
		dsn = getEnv("DATABASE_DSN", getEnv("DATABASE_PATH", "oauth.db"))
	} else {
		dsn = getEnv("DATABASE_DSN", "")
	}

	// Resolve base JWT settings first — the "standard" profile inherits these,
	// so the map must be built after the values are known.
	jwtExpiration := getEnvDuration("JWT_EXPIRATION", 10*time.Hour)
	refreshTokenExpiration := getEnvDuration("REFRESH_TOKEN_EXPIRATION", 720*time.Hour)
	tokenProfiles := map[string]TokenProfile{
		models.TokenProfileShort: {
			AccessTokenTTL:  getEnvDuration("TOKEN_PROFILE_SHORT_ACCESS_TTL", 15*time.Minute),
			RefreshTokenTTL: getEnvDuration("TOKEN_PROFILE_SHORT_REFRESH_TTL", 24*time.Hour),
		},
		models.TokenProfileStandard: {
			AccessTokenTTL: getEnvDuration("TOKEN_PROFILE_STANDARD_ACCESS_TTL", jwtExpiration),
			RefreshTokenTTL: getEnvDuration(
				"TOKEN_PROFILE_STANDARD_REFRESH_TTL",
				refreshTokenExpiration,
			),
		},
		models.TokenProfileLong: {
			AccessTokenTTL: getEnvDuration("TOKEN_PROFILE_LONG_ACCESS_TTL", 24*time.Hour),
			RefreshTokenTTL: getEnvDuration(
				"TOKEN_PROFILE_LONG_REFRESH_TTL",
				2160*time.Hour,
			), // 90 days
		},
	}

	return &Config{
		ServerAddr:  getEnv("SERVER_ADDR", ":8080"),
		BaseURL:     getEnv("BASE_URL", "http://localhost:8080"),
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
		IsProduction: getEnvBool("ENVIRONMENT", false) ||
			getEnv("ENVIRONMENT", "") == "production",
		SwaggerEnabled:      getEnvBool("ENABLE_SWAGGER", false),
		JWTSecret:           getEnv("JWT_SECRET", "your-256-bit-secret-change-in-production"),
		JWTExpiration:       jwtExpiration,
		JWTSigningAlgorithm: getEnv("JWT_SIGNING_ALGORITHM", AlgHS256),
		JWTPrivateKeyPath:   getEnv("JWT_PRIVATE_KEY_PATH", ""),
		JWTPrivateKeyPEM:    getEnv("JWT_PRIVATE_KEY_PEM", ""),
		JWTKeyID:            getEnv("JWT_KEY_ID", ""),
		JWTExpirationJitter: getEnvDuration("JWT_EXPIRATION_JITTER", 30*time.Minute),
		JWTAudience:         getEnvSlice("JWT_AUDIENCE", nil),
		JWTDomain:           strings.TrimSpace(getEnv("JWT_DOMAIN", "")),
		JWTPrivateClaimPrefix: strings.TrimSpace(
			getEnv("JWT_PRIVATE_CLAIM_PREFIX", DefaultJWTPrivateClaimPrefix),
		),
		SessionSecret:      getEnv("SESSION_SECRET", "session-secret-change-in-production"),
		SessionMaxAge:      getEnvInt("SESSION_MAX_AGE", 3600),      // 1 hour default
		SessionIdleTimeout: getEnvInt("SESSION_IDLE_TIMEOUT", 1800), // 30 minutes default
		SessionFingerprint: getEnvBool("SESSION_FINGERPRINT", true), // Enabled by default
		SessionFingerprintIP: getEnvBool(
			"SESSION_FINGERPRINT_IP",
			false,
		), // Disabled by default (dynamic IPs)
		SessionRememberMeEnabled: getEnvBool("SESSION_REMEMBER_ME_ENABLED", true),
		SessionRememberMeMaxAge:  getEnvInt("SESSION_REMEMBER_ME_MAX_AGE", 2592000), // 30 days
		DeviceCodeExpiration:     30 * time.Minute,
		PollingInterval:          5,
		DatabaseDriver:           driver,
		DatabaseDSN:              dsn,
		DBMaxOpenConns:           getEnvInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:           getEnvInt("DB_MAX_IDLE_CONNS", 10),
		DBConnMaxLifetime:        getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		DBConnMaxIdleTime:        getEnvDuration("DB_CONN_MAX_IDLE_TIME", 10*time.Minute),
		DBLogLevel:               getEnv("DB_LOG_LEVEL", "warn"),

		// Default Admin User
		DefaultAdminPassword: getEnv("DEFAULT_ADMIN_PASSWORD", ""),

		// Authentication
		AuthMode: getEnv("AUTH_MODE", AuthModeLocal),

		// HTTP API Authentication
		HTTPAPIURL:                getEnv("HTTP_API_URL", ""),
		HTTPAPITimeout:            getEnvDuration("HTTP_API_TIMEOUT", 10*time.Second),
		HTTPAPIInsecureSkipVerify: getEnvBool("HTTP_API_INSECURE_SKIP_VERIFY", false),
		HTTPAPIAuthMode:           getEnv("HTTP_API_AUTH_MODE", "none"),
		HTTPAPIAuthSecret:         getEnv("HTTP_API_AUTH_SECRET", ""),
		HTTPAPIAuthHeader:         getEnv("HTTP_API_AUTH_HEADER", "X-API-Secret"),
		HTTPAPIMaxRetries:         getEnvInt("HTTP_API_MAX_RETRIES", 3),
		HTTPAPIRetryDelay:         getEnvDuration("HTTP_API_RETRY_DELAY", 1*time.Second),
		HTTPAPIMaxRetryDelay:      getEnvDuration("HTTP_API_MAX_RETRY_DELAY", 10*time.Second),

		// Refresh Token settings
		RefreshTokenExpiration:    refreshTokenExpiration,
		EnableRefreshTokens:       getEnvBool("ENABLE_REFRESH_TOKENS", true),
		EnableTokenRotation:       getEnvBool("ENABLE_TOKEN_ROTATION", false),
		JWTExpirationMax:          getEnvDuration("JWT_EXPIRATION_MAX", 24*time.Hour),
		RefreshTokenExpirationMax: getEnvDuration("REFRESH_TOKEN_EXPIRATION_MAX", 2160*time.Hour),
		TokenProfiles:             tokenProfiles,

		// Client Credentials Flow settings
		ClientCredentialsTokenExpiration: getEnvDuration(
			"CLIENT_CREDENTIALS_TOKEN_EXPIRATION",
			time.Hour,
		), // 1 hour default; keep short — no refresh token means no rotation mechanism

		// Caller-supplied JWT extra claims (extra_claims on /oauth/token).
		// Enabled by default — reserved JWT/OIDC keys are still rejected, and
		// the issuer's standard claims always override any caller value.
		ExtraClaimsEnabled:    getEnvBool("EXTRA_CLAIMS_ENABLED", true),
		ExtraClaimsMaxRawSize: getEnvInt("EXTRA_CLAIMS_MAX_RAW_SIZE", 4096),
		ExtraClaimsMaxKeys:    getEnvInt("EXTRA_CLAIMS_MAX_KEYS", 16),
		ExtraClaimsMaxValSize: getEnvInt("EXTRA_CLAIMS_MAX_VAL_SIZE", 512),

		// OAuth settings
		// GitHub OAuth
		GitHubOAuthEnabled:     getEnvBool("GITHUB_OAUTH_ENABLED", false),
		GitHubClientID:         getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:     getEnv("GITHUB_CLIENT_SECRET", ""),
		GitHubOAuthRedirectURL: getEnv("GITHUB_REDIRECT_URL", ""),
		GitHubOAuthScopes:      getEnvSlice("GITHUB_SCOPES", []string{"user:email"}),

		// Gitea OAuth
		GiteaOAuthEnabled:     getEnvBool("GITEA_OAUTH_ENABLED", false),
		GiteaURL:              getEnv("GITEA_URL", ""),
		GiteaClientID:         getEnv("GITEA_CLIENT_ID", ""),
		GiteaClientSecret:     getEnv("GITEA_CLIENT_SECRET", ""),
		GiteaOAuthRedirectURL: getEnv("GITEA_REDIRECT_URL", ""),
		GiteaOAuthScopes:      getEnvSlice("GITEA_SCOPES", []string{"read:user"}),

		// Microsoft Entra ID OAuth
		MicrosoftOAuthEnabled:     getEnvBool("MICROSOFT_OAUTH_ENABLED", false),
		MicrosoftTenantID:         getEnv("MICROSOFT_TENANT_ID", "common"),
		MicrosoftClientID:         getEnv("MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret:     getEnv("MICROSOFT_CLIENT_SECRET", ""),
		MicrosoftOAuthRedirectURL: getEnv("MICROSOFT_REDIRECT_URL", ""),
		MicrosoftOAuthScopes: getEnvSlice(
			"MICROSOFT_SCOPES",
			[]string{"openid", "profile", "email", "User.Read"},
		),

		// GitLab OAuth
		GitLabOAuthEnabled:     getEnvBool("GITLAB_OAUTH_ENABLED", false),
		GitLabURL:              getEnv("GITLAB_URL", ""),
		GitLabClientID:         getEnv("GITLAB_CLIENT_ID", ""),
		GitLabClientSecret:     getEnv("GITLAB_CLIENT_SECRET", ""),
		GitLabOAuthRedirectURL: getEnv("GITLAB_REDIRECT_URL", ""),
		GitLabOAuthScopes:      getEnvSlice("GITLAB_SCOPES", []string{"read_user"}),

		// OAuth Auto Registration
		OAuthAutoRegister: getEnvBool("OAUTH_AUTO_REGISTER", true),

		// OAuth HTTP Client Settings
		OAuthTimeout:            getEnvDuration("OAUTH_TIMEOUT", 15*time.Second),
		OAuthInsecureSkipVerify: getEnvBool("OAUTH_INSECURE_SKIP_VERIFY", false),

		// Rate Limiting settings
		EnableRateLimit:          getEnvBool("ENABLE_RATE_LIMIT", true),
		RateLimitStore:           getEnv("RATE_LIMIT_STORE", "memory"),
		RateLimitCleanupInterval: getEnvDuration("RATE_LIMIT_CLEANUP_INTERVAL", 5*time.Minute),
		LoginRateLimit:           getEnvInt("LOGIN_RATE_LIMIT", 5),
		DeviceCodeRateLimit:      getEnvInt("DEVICE_CODE_RATE_LIMIT", 10),
		TokenRateLimit:           getEnvInt("TOKEN_RATE_LIMIT", 20),
		DeviceVerifyRateLimit:    getEnvInt("DEVICE_VERIFY_RATE_LIMIT", 10),
		IntrospectRateLimit:      getEnvInt("INTROSPECT_RATE_LIMIT", 20),

		// Redis settings
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvInt("REDIS_DB", 0),

		// Audit Logging settings
		EnableAuditLogging:      getEnvBool("ENABLE_AUDIT_LOGGING", true),
		AuditLogRetention:       getEnvDuration("AUDIT_LOG_RETENTION", 90*24*time.Hour), // 90 days
		AuditLogBufferSize:      getEnvInt("AUDIT_LOG_BUFFER_SIZE", 1000),
		AuditLogCleanupInterval: getEnvDuration("AUDIT_LOG_CLEANUP_INTERVAL", 24*time.Hour),

		// Token/Device Code cleanup settings
		EnableExpiredTokenCleanup:   getEnvBool("ENABLE_EXPIRED_TOKEN_CLEANUP", false),
		ExpiredTokenCleanupInterval: getEnvDuration("EXPIRED_TOKEN_CLEANUP_INTERVAL", time.Hour),

		// Prometheus Metrics settings
		MetricsEnabled:             getEnvBool("METRICS_ENABLED", false),
		MetricsToken:               getEnv("METRICS_TOKEN", ""),
		MetricsGaugeUpdateEnabled:  getEnvBool("METRICS_GAUGE_UPDATE_ENABLED", true),
		MetricsGaugeUpdateInterval: getEnvDuration("METRICS_GAUGE_UPDATE_INTERVAL", 5*time.Minute),
		MetricsCacheType:           getEnv("METRICS_CACHE_TYPE", CacheTypeMemory),
		MetricsCacheClientTTL:      getEnvDuration("METRICS_CACHE_CLIENT_TTL", 30*time.Second),
		MetricsCacheSizePerConn:    getEnvInt("METRICS_CACHE_SIZE_PER_CONN", 32), // 32MB default

		// User Cache settings
		UserCacheType:        getEnv("USER_CACHE_TYPE", CacheTypeMemory),
		UserCacheTTL:         getEnvDuration("USER_CACHE_TTL", 5*time.Minute),
		UserCacheClientTTL:   getEnvDuration("USER_CACHE_CLIENT_TTL", 30*time.Second),
		UserCacheSizePerConn: getEnvInt("USER_CACHE_SIZE_PER_CONN", 32), // 32MB default

		// Client Count Cache settings
		ClientCountCacheType:      getEnv("CLIENT_COUNT_CACHE_TYPE", CacheTypeMemory),
		ClientCountCacheTTL:       getEnvDuration("CLIENT_COUNT_CACHE_TTL", time.Hour),
		ClientCountCacheClientTTL: getEnvDuration("CLIENT_COUNT_CACHE_CLIENT_TTL", 10*time.Minute),
		ClientCountCacheSizePerConn: getEnvInt(
			"CLIENT_COUNT_CACHE_SIZE_PER_CONN",
			32,
		), // 32MB default

		// Client Cache settings
		ClientCacheType:        getEnv("CLIENT_CACHE_TYPE", CacheTypeMemory),
		ClientCacheTTL:         getEnvDuration("CLIENT_CACHE_TTL", 5*time.Minute),
		ClientCacheClientTTL:   getEnvDuration("CLIENT_CACHE_CLIENT_TTL", 30*time.Second),
		ClientCacheSizePerConn: getEnvInt("CLIENT_CACHE_SIZE_PER_CONN", 32), // 32MB default

		// Token Cache settings
		TokenCacheEnabled:     getEnvBool("TOKEN_CACHE_ENABLED", false),
		TokenCacheType:        getEnv("TOKEN_CACHE_TYPE", CacheTypeMemory),
		TokenCacheTTL:         getEnvDuration("TOKEN_CACHE_TTL", 10*time.Hour),
		TokenCacheClientTTL:   getEnvDuration("TOKEN_CACHE_CLIENT_TTL", time.Hour),
		TokenCacheSizePerConn: getEnvInt("TOKEN_CACHE_SIZE_PER_CONN", 32), // 32MB default

		// Dynamic Client Registration (RFC 7591)
		EnableDynamicClientRegistration:    getEnvBool("ENABLE_DYNAMIC_CLIENT_REGISTRATION", false),
		DynamicClientRegistrationRateLimit: getEnvInt("DYNAMIC_CLIENT_REGISTRATION_RATE_LIMIT", 5),
		DynamicClientRegistrationToken:     getEnv("DYNAMIC_CLIENT_REGISTRATION_TOKEN", ""),

		// Authorization Code Flow settings
		AuthCodeExpiration: getEnvDuration("AUTH_CODE_EXPIRATION", 10*time.Minute),
		PKCERequired:       getEnvBool("PKCE_REQUIRED", false),
		ConsentRemember:    getEnvBool("CONSENT_REMEMBER", true),

		// Bootstrap and shutdown timeout settings
		DBInitTimeout:         getEnvDuration("DB_INIT_TIMEOUT", 30*time.Second),
		RedisConnTimeout:      getEnvDuration("REDIS_CONN_TIMEOUT", 5*time.Second),
		CacheInitTimeout:      getEnvDuration("CACHE_INIT_TIMEOUT", 5*time.Second),
		ServerShutdownTimeout: getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 5*time.Second),
		AuditShutdownTimeout:  getEnvDuration("AUDIT_SHUTDOWN_TIMEOUT", 10*time.Second),
		RedisCloseTimeout:     getEnvDuration("REDIS_CLOSE_TIMEOUT", 5*time.Second),
		CacheCloseTimeout:     getEnvDuration("CACHE_CLOSE_TIMEOUT", 5*time.Second),
		DBCloseTimeout:        getEnvDuration("DB_CLOSE_TIMEOUT", 5*time.Second),

		// CORS
		CORSEnabled:        getEnvBool("CORS_ENABLED", false),
		CORSAllowedOrigins: getEnvSlice("CORS_ALLOWED_ORIGINS", nil),
		CORSAllowedMethods: getEnvSlice(
			"CORS_ALLOWED_METHODS",
			[]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		),
		CORSAllowedHeaders: getEnvSlice(
			"CORS_ALLOWED_HEADERS",
			[]string{"Origin", "Content-Type", "Authorization"},
		),
		CORSMaxAge: getEnvDuration("CORS_MAX_AGE", 12*time.Hour),

		// Static file caching
		StaticCacheMaxAge: getEnvDuration("STATIC_CACHE_MAX_AGE", 24*time.Hour),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var i int
		if _, err := fmt.Sscanf(value, "%d", &i); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		if parts := splitAndTrim(value, ","); len(parts) > 0 {
			return parts
		}
	}
	return defaultValue
}

func splitAndTrim(s, sep string) []string {
	var out []string
	for part := range strings.SplitSeq(s, sep) {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// validateCacheType checks that value is a recognised cache type and, when
// redis-based, that a Redis address has been configured.
func validateCacheType(name, value, redisAddr string) error {
	if value != CacheTypeMemory && value != CacheTypeRedis && value != CacheTypeRedisAside {
		return fmt.Errorf(
			"invalid %s value: %q (must be %q, %q, or %q)",
			name, value, CacheTypeMemory, CacheTypeRedis, CacheTypeRedisAside,
		)
	}
	if (value == CacheTypeRedis || value == CacheTypeRedisAside) && redisAddr == "" {
		return fmt.Errorf("%s=%q requires REDIS_ADDR to be configured", name, value)
	}
	return nil
}

// Validate checks the configuration for invalid values
func (c *Config) Validate() error {
	// Validate JWT expiration
	if c.JWTExpiration <= 0 {
		return fmt.Errorf("JWT_EXPIRATION must be a positive duration (got %s)", c.JWTExpiration)
	}

	// Validate JWT expiration jitter
	if c.JWTExpirationJitter < 0 {
		return fmt.Errorf(
			"JWT_EXPIRATION_JITTER must be non-negative (got %s)",
			c.JWTExpirationJitter,
		)
	}

	// Validate caller-supplied extra-claims size limits. 0 means "disabled";
	// negative values would silently disable the check too because every limit
	// is gated on `> 0`, so reject them up-front to avoid surprises.
	if c.ExtraClaimsMaxRawSize < 0 {
		return fmt.Errorf(
			"EXTRA_CLAIMS_MAX_RAW_SIZE must be non-negative (got %d)",
			c.ExtraClaimsMaxRawSize,
		)
	}
	if c.ExtraClaimsMaxKeys < 0 {
		return fmt.Errorf(
			"EXTRA_CLAIMS_MAX_KEYS must be non-negative (got %d)",
			c.ExtraClaimsMaxKeys,
		)
	}
	if c.ExtraClaimsMaxValSize < 0 {
		return fmt.Errorf(
			"EXTRA_CLAIMS_MAX_VAL_SIZE must be non-negative (got %d)",
			c.ExtraClaimsMaxValSize,
		)
	}
	if c.JWTExpirationJitter > 0 && c.JWTExpirationJitter >= c.JWTExpiration {
		return fmt.Errorf(
			"JWT_EXPIRATION_JITTER must be less than JWT_EXPIRATION (%s >= %s)",
			c.JWTExpirationJitter, c.JWTExpiration,
		)
	}

	// Validate JWT_DOMAIN identifier shape. Empty string is the documented
	// "feature off" value and never errors; otherwise the value must satisfy
	// the same identifier pattern as the per-client `project` claim so that
	// downstream consumers can match it byte-for-byte.
	if c.JWTDomain != "" && !util.IsValidProjectIdentifier(c.JWTDomain) {
		return fmt.Errorf(
			"invalid JWT_DOMAIN value: %q (must be 1–64 characters of letters, digits, "+
				"underscore, dot, or hyphen, starting and ending with a letter or digit)",
			c.JWTDomain,
		)
	}

	if err := c.validateJWTPrivateClaimPrefix(); err != nil {
		return err
	}

	// Validate JWT secret minimum length for HS256
	if (c.JWTSigningAlgorithm == "" || c.JWTSigningAlgorithm == AlgHS256) && len(c.JWTSecret) < 32 {
		return fmt.Errorf(
			"JWT_SECRET must be at least 32 bytes for HS256 (got %d bytes)",
			len(c.JWTSecret),
		)
	}

	// Validate JWT signing algorithm
	switch c.JWTSigningAlgorithm {
	case "", AlgHS256:
		// default, no key file required
	case AlgRS256, AlgES256:
		if c.JWTPrivateKeyPath == "" && c.JWTPrivateKeyPEM == "" {
			return fmt.Errorf(
				"JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM is required when JWT_SIGNING_ALGORITHM=%s",
				c.JWTSigningAlgorithm,
			)
		}
	default:
		return fmt.Errorf(
			"invalid JWT_SIGNING_ALGORITHM value: %q (must be \"HS256\", \"RS256\", or \"ES256\")",
			c.JWTSigningAlgorithm,
		)
	}

	// TLS cert/key must be set together — setting only one would silently fall back to HTTP.
	if (c.TLSCertFile != "") != (c.TLSKeyFile != "") {
		return errors.New("TLS_CERT_FILE and TLS_KEY_FILE must both be set or both be empty")
	}

	// Validate rate limit store type
	if c.RateLimitStore != RateLimitStoreMemory && c.RateLimitStore != RateLimitStoreRedis {
		return fmt.Errorf(
			"invalid RATE_LIMIT_STORE value: %q (must be %q or %q)",
			c.RateLimitStore,
			RateLimitStoreMemory,
			RateLimitStoreRedis,
		)
	}

	if err := validateCacheType("METRICS_CACHE_TYPE", c.MetricsCacheType, c.RedisAddr); err != nil {
		return err
	}

	if err := validateCacheType("USER_CACHE_TYPE", c.UserCacheType, c.RedisAddr); err != nil {
		return err
	}

	// USER_CACHE_TTL must be positive
	if c.UserCacheTTL <= 0 {
		return fmt.Errorf(
			"USER_CACHE_TTL must be a positive duration (got %s)",
			c.UserCacheTTL,
		)
	}

	// USER_CACHE_CLIENT_TTL must be positive when using redis-aside
	if c.UserCacheType == CacheTypeRedisAside && c.UserCacheClientTTL <= 0 {
		return fmt.Errorf(
			"USER_CACHE_CLIENT_TTL must be a positive duration when USER_CACHE_TYPE=%q (got %s)",
			CacheTypeRedisAside, c.UserCacheClientTTL,
		)
	}

	if err := validateCacheType(
		"CLIENT_COUNT_CACHE_TYPE",
		c.ClientCountCacheType,
		c.RedisAddr,
	); err != nil {
		return err
	}

	// CLIENT_COUNT_CACHE_TTL must be positive
	if c.ClientCountCacheTTL <= 0 {
		return fmt.Errorf(
			"CLIENT_COUNT_CACHE_TTL must be a positive duration (got %s)",
			c.ClientCountCacheTTL,
		)
	}

	// Client Cache validation
	if err := validateCacheType("CLIENT_CACHE_TYPE", c.ClientCacheType, c.RedisAddr); err != nil {
		return err
	}
	if c.ClientCacheTTL <= 0 {
		return fmt.Errorf(
			"CLIENT_CACHE_TTL must be a positive duration (got %s)",
			c.ClientCacheTTL,
		)
	}
	if c.ClientCacheType == CacheTypeRedisAside && c.ClientCacheClientTTL <= 0 {
		return fmt.Errorf(
			"CLIENT_CACHE_CLIENT_TTL must be a positive duration when CLIENT_CACHE_TYPE=%q (got %s)",
			CacheTypeRedisAside,
			c.ClientCacheClientTTL,
		)
	}

	// Token cache validation (only when enabled)
	if c.TokenCacheEnabled {
		if err := validateCacheType("TOKEN_CACHE_TYPE", c.TokenCacheType, c.RedisAddr); err != nil {
			return err
		}
		if c.TokenCacheTTL <= 0 {
			return fmt.Errorf(
				"TOKEN_CACHE_TTL must be a positive duration when TOKEN_CACHE_ENABLED=true (got %s)",
				c.TokenCacheTTL,
			)
		}
		if c.TokenCacheType == CacheTypeRedisAside && c.TokenCacheClientTTL <= 0 {
			return fmt.Errorf(
				"TOKEN_CACHE_CLIENT_TTL must be a positive duration when TOKEN_CACHE_TYPE=%q (got %s)",
				CacheTypeRedisAside,
				c.TokenCacheClientTTL,
			)
		}
	}

	// SESSION_REMEMBER_ME_MAX_AGE must be positive when remember-me is enabled.
	// The gorilla/sessions cookie store codec has a default max-age of 30 days;
	// values above 2592000 (30 days) may cause cookie decode failures.
	if c.SessionRememberMeEnabled && c.SessionRememberMeMaxAge <= 0 {
		return fmt.Errorf(
			"SESSION_REMEMBER_ME_MAX_AGE must be a positive value when SESSION_REMEMBER_ME_ENABLED=true (got %d)",
			c.SessionRememberMeMaxAge,
		)
	}
	if c.SessionRememberMeEnabled && c.SessionRememberMeMaxAge > 2592000 {
		return fmt.Errorf(
			"SESSION_REMEMBER_ME_MAX_AGE exceeds 30-day gorilla/sessions limit (got %d, max 2592000)",
			c.SessionRememberMeMaxAge,
		)
	}

	return c.validateTokenProfiles()
}

// validateJWTPrivateClaimPrefix enforces the prefix shape and ensures no
// composed `<prefix>_<logical>` key collides with a static reserved claim key.
// Trailing-underscore is rejected explicitly (not via the regex) so the error
// message can name the cause.
//
// An empty prefix is treated as "use the default" — matching Load()
// (which substitutes DefaultJWTPrivateClaimPrefix when the env var is unset
// or empty) and the runtime layers (NewExtraClaimsParser /
// NewLocalTokenProvider / NewTokenService all default empty → default).
// Without this normalization, ad-hoc Config{} fixtures would surface an
// empty-prefix error from Validate() while the rest of the codebase
// silently substitutes the default — an inconsistency that produced
// confusing test failures.
func (c *Config) validateJWTPrivateClaimPrefix() error {
	prefix := c.JWTPrivateClaimPrefix
	if prefix == "" {
		prefix = DefaultJWTPrivateClaimPrefix
	}
	if len(prefix) > jwtPrivateClaimPrefixMaxLen {
		return fmt.Errorf(
			"JWT_PRIVATE_CLAIM_PREFIX must be at most %d characters (got %d: %q)",
			jwtPrivateClaimPrefixMaxLen, len(prefix), prefix,
		)
	}
	if strings.HasSuffix(prefix, "_") {
		return fmt.Errorf(
			"JWT_PRIVATE_CLAIM_PREFIX must not end with an underscore "+
				"(AuthGate adds the separator itself; trailing _ would produce "+
				"a double underscore in claim names): %q",
			prefix,
		)
	}
	if !jwtPrivateClaimPrefixPattern.MatchString(prefix) {
		return fmt.Errorf(
			"JWT_PRIVATE_CLAIM_PREFIX must match %s (got %q)",
			jwtPrivateClaimPrefixPattern.String(), prefix,
		)
	}

	return detectPrefixCollision(
		prefix, jwtPrivateClaimLogicalNames, staticReservedClaimKeys,
	)
}

// detectPrefixCollision returns an error if any composed key
// `<prefix>_<logical>` (for logical in logicalNames) collides with a key
// in reservedKeys. Pure function, no globals — pass in the lists so the
// test can exercise the collision branch with a synthetic logicalNames
// slice without mutating any package-level state.
func detectPrefixCollision(prefix string, logicalNames, reservedKeys []string) error {
	reserved := make(map[string]struct{}, len(reservedKeys))
	for _, k := range reservedKeys {
		reserved[k] = struct{}{}
	}
	for _, logical := range logicalNames {
		composed := prefix + "_" + logical
		if _, clash := reserved[composed]; clash {
			return fmt.Errorf(
				"JWT_PRIVATE_CLAIM_PREFIX %q produces composed claim key %q "+
					"which collides with a reserved RFC/OIDC/AuthGate-internal claim",
				prefix, composed,
			)
		}
	}
	return nil
}

// validateTokenProfiles checks that every profile has positive TTLs and that
// no profile's TTL exceeds the configured hard caps (JWT_EXPIRATION_MAX /
// REFRESH_TOKEN_EXPIRATION_MAX). The standard / short / long profiles must all
// be present. When TokenProfiles and both caps are left at their zero values
// (e.g. a hand-built *Config used in an ad-hoc unit test) validation is
// skipped — Load() always populates these, so this gate only affects real
// startup, not consumers who only care about unrelated fields.
func (c *Config) validateTokenProfiles() error {
	if len(c.TokenProfiles) == 0 && c.JWTExpirationMax == 0 && c.RefreshTokenExpirationMax == 0 {
		return nil
	}
	if c.JWTExpirationMax <= 0 {
		return fmt.Errorf(
			"JWT_EXPIRATION_MAX must be a positive duration (got %s)",
			c.JWTExpirationMax,
		)
	}
	if c.RefreshTokenExpirationMax <= 0 {
		return fmt.Errorf(
			"REFRESH_TOKEN_EXPIRATION_MAX must be a positive duration (got %s)",
			c.RefreshTokenExpirationMax,
		)
	}

	requiredProfiles := []string{
		models.TokenProfileShort,
		models.TokenProfileStandard,
		models.TokenProfileLong,
	}
	for _, name := range requiredProfiles {
		profile, ok := c.TokenProfiles[name]
		if !ok {
			return fmt.Errorf("token profile %q is missing from TokenProfiles", name)
		}
		if profile.AccessTokenTTL <= 0 {
			return fmt.Errorf(
				"token profile %q access TTL must be a positive duration (got %s)",
				name, profile.AccessTokenTTL,
			)
		}
		if profile.RefreshTokenTTL <= 0 {
			return fmt.Errorf(
				"token profile %q refresh TTL must be a positive duration (got %s)",
				name, profile.RefreshTokenTTL,
			)
		}
		if profile.AccessTokenTTL > c.JWTExpirationMax {
			return fmt.Errorf(
				"token profile %q access TTL %s exceeds JWT_EXPIRATION_MAX %s",
				name, profile.AccessTokenTTL, c.JWTExpirationMax,
			)
		}
		if profile.RefreshTokenTTL > c.RefreshTokenExpirationMax {
			return fmt.Errorf(
				"token profile %q refresh TTL %s exceeds REFRESH_TOKEN_EXPIRATION_MAX %s",
				name, profile.RefreshTokenTTL, c.RefreshTokenExpirationMax,
			)
		}
	}
	return nil
}
