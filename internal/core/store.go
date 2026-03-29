package core

import (
	"context"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store/types"
)

// ── User ────────────────────────────────────────────────────────────────

// UserReader groups read-only user lookup operations.
type UserReader interface {
	GetUserByUsername(username string) (*models.User, error)
	GetUserByID(id string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	GetUserByExternalID(externalID, authSource string) (*models.User, error)
	GetUsersByIDs(userIDs []string) (map[string]*models.User, error)
}

// UserWriter groups user mutation operations.
type UserWriter interface {
	CreateUser(user *models.User) error
	UpdateUser(user *models.User) error
	DeleteUser(id string) error
	UpsertExternalUser(
		username, externalID, authSource, email, fullName string,
	) (*models.User, error)
}

// ── OAuth Client ────────────────────────────────────────────────────────

// ClientReader groups read-only client operations.
type ClientReader interface {
	GetClient(clientID string) (*models.OAuthApplication, error)
	GetClientByIntID(id int64) (*models.OAuthApplication, error)
	GetClientsByIDs(clientIDs []string) (map[string]*models.OAuthApplication, error)
	ListClientsPaginated(
		params types.PaginationParams,
	) ([]models.OAuthApplication, types.PaginationResult, error)
	ListClientsByUserID(
		userID string,
		params types.PaginationParams,
	) ([]models.OAuthApplication, types.PaginationResult, error)
	CountClientsByStatus(status string) (int64, error)
	CountActiveTokensByClientID(clientID string) (int64, error)
}

// ClientWriter groups client mutation operations.
type ClientWriter interface {
	CreateClient(client *models.OAuthApplication) error
	UpdateClient(client *models.OAuthApplication) error
	DeleteClient(clientID string) error
}

// ── Device Code ─────────────────────────────────────────────────────────

// DeviceCodeStore groups device code operations.
type DeviceCodeStore interface {
	CreateDeviceCode(dc *models.DeviceCode) error
	GetDeviceCodesByID(deviceCodeID string) ([]*models.DeviceCode, error)
	GetDeviceCodeByUserCode(userCode string) (*models.DeviceCode, error)
	UpdateDeviceCode(dc *models.DeviceCode) error
	DeleteDeviceCodeByID(id int64) error
}

// ── Access Token ────────────────────────────────────────────────────────

// TokenReader groups read-only token operations.
type TokenReader interface {
	GetAccessTokenByHash(hash string) (*models.AccessToken, error)
	GetAccessTokenByID(tokenID string) (*models.AccessToken, error)
	GetTokensByUserID(userID string) ([]models.AccessToken, error)
	GetTokensByUserIDPaginated(
		userID string,
		params types.PaginationParams,
	) ([]models.AccessToken, types.PaginationResult, error)
	GetTokensByCategoryAndStatus(userID, category, status string) ([]models.AccessToken, error)
	GetActiveTokenHashesByFamilyID(familyID string) ([]string, error)
	GetActiveTokenHashesByAuthorizationID(authorizationID uint) ([]string, error)
	GetActiveTokenHashesByClientID(clientID string) ([]string, error)
}

// TokenWriter groups token mutation operations.
type TokenWriter interface {
	CreateAccessToken(token *models.AccessToken) error
	RevokeToken(tokenID string) error
	RevokeTokensByUserID(userID string) error
	RevokeTokensByClientID(clientID string) error
	RevokeTokenFamily(familyID string) (int64, error)
	UpdateTokenStatus(tokenID, status string) error
	UpdateTokenLastUsedAt(tokenID string, t time.Time) error
	RevokeTokensByAuthorizationID(authorizationID uint) error
	RevokeAllActiveTokensByClientID(clientID string) (int64, error)
}

// ── Authorization Code ──────────────────────────────────────────────────

// AuthorizationCodeStore groups authorization code operations.
type AuthorizationCodeStore interface {
	CreateAuthorizationCode(code *models.AuthorizationCode) error
	GetAuthorizationCodeByHash(hash string) (*models.AuthorizationCode, error)
	MarkAuthorizationCodeUsed(id uint) error
}

// ── User Authorization (Consent) ────────────────────────────────────────

// UserAuthorizationStore groups per-app consent grant operations.
type UserAuthorizationStore interface {
	GetUserAuthorization(userID string, applicationID int64) (*models.UserAuthorization, error)
	GetUserAuthorizationByUUID(authUUID, userID string) (*models.UserAuthorization, error)
	UpsertUserAuthorization(auth *models.UserAuthorization) error
	RevokeUserAuthorization(authUUID, userID string) (*models.UserAuthorization, error)
	ListUserAuthorizations(userID string) ([]models.UserAuthorization, error)
	GetClientAuthorizations(clientID string) ([]models.UserAuthorization, error)
	RevokeAllUserAuthorizationsByClientID(clientID string) error
}

// ── OAuth Connection ────────────────────────────────────────────────────

// OAuthConnectionStore groups external OAuth connection operations.
type OAuthConnectionStore interface {
	CreateOAuthConnection(conn *models.OAuthConnection) error
	GetOAuthConnection(provider, providerUserID string) (*models.OAuthConnection, error)
	GetOAuthConnectionByUserAndProvider(userID, provider string) (*models.OAuthConnection, error)
	GetOAuthConnectionsByUserID(userID string) ([]models.OAuthConnection, error)
	UpdateOAuthConnection(conn *models.OAuthConnection) error
	DeleteOAuthConnection(id string) error
}

// ── Audit Log ───────────────────────────────────────────────────────────

// AuditStore groups audit log operations.
type AuditStore interface {
	CreateAuditLog(log *models.AuditLog) error
	CreateAuditLogBatch(logs []*models.AuditLog) error
	GetAuditLogsPaginated(
		params types.PaginationParams,
		filters types.AuditLogFilters,
	) ([]models.AuditLog, types.PaginationResult, error)
	DeleteOldAuditLogs(olderThan time.Time) (int64, error)
	GetAuditLogStats(startTime, endTime time.Time) (types.AuditLogStats, error)
}

// ── Cleanup ─────────────────────────────────────────────────────────────

// CleanupStore groups expired-data cleanup operations.
type CleanupStore interface {
	DeleteExpiredTokens() error
	DeleteExpiredDeviceCodes() error
}

// ── Transaction ─────────────────────────────────────────────────────────

// Transactor provides database transaction support.
type Transactor interface {
	RunInTransaction(fn func(tx Store) error) error
}

// ── Infrastructure ──────────────────────────────────────────────────────

// Infrastructure groups lifecycle and health operations.
type Infrastructure interface {
	Close(ctx context.Context) error
	Health() error
}

// ── Aggregate ───────────────────────────────────────────────────────────

// Store is the aggregate data-access interface.
// Services accept this; the composition root passes the concrete *store.Store.
type Store interface {
	UserReader
	UserWriter
	ClientReader
	ClientWriter
	DeviceCodeStore
	TokenReader
	TokenWriter
	AuthorizationCodeStore
	UserAuthorizationStore
	OAuthConnectionStore
	AuditStore
	MetricsStore
	CleanupStore
	Transactor
	Infrastructure
}
