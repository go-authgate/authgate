package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	// Authentication events
	EventAuthenticationSuccess EventType = "AUTHENTICATION_SUCCESS"
	EventAuthenticationFailure EventType = "AUTHENTICATION_FAILURE"
	EventLogout                EventType = "LOGOUT"
	EventOAuthAuthentication   EventType = "OAUTH_AUTHENTICATION"

	// Device authorization events
	EventDeviceCodeGenerated  EventType = "DEVICE_CODE_GENERATED"
	EventDeviceCodeAuthorized EventType = "DEVICE_CODE_AUTHORIZED"

	// Token events
	EventAccessTokenIssued  EventType = "ACCESS_TOKEN_ISSUED"
	EventRefreshTokenIssued EventType = "REFRESH_TOKEN_ISSUED"
	EventTokenRefreshed     EventType = "TOKEN_REFRESHED"
	EventTokenRevoked       EventType = "TOKEN_REVOKED"
	EventTokenDisabled      EventType = "TOKEN_DISABLED"
	EventTokenEnabled       EventType = "TOKEN_ENABLED"

	// Admin operations
	EventClientCreated           EventType = "CLIENT_CREATED"
	EventClientUpdated           EventType = "CLIENT_UPDATED"
	EventClientDeleted           EventType = "CLIENT_DELETED"
	EventClientSecretRegenerated EventType = "CLIENT_SECRET_REGENERATED"

	// Security events
	EventRateLimitExceeded  EventType = "RATE_LIMIT_EXCEEDED"
	EventSuspiciousActivity EventType = "SUSPICIOUS_ACTIVITY"

	// Authorization Code Flow events (RFC 6749)
	EventAuthorizationCodeGenerated EventType = "AUTHORIZATION_CODE_GENERATED"
	EventAuthorizationCodeExchanged EventType = "AUTHORIZATION_CODE_EXCHANGED"
	EventAuthorizationCodeDenied    EventType = "AUTHORIZATION_CODE_DENIED"
	EventUserAuthorizationGranted   EventType = "USER_AUTHORIZATION_GRANTED"
	EventUserAuthorizationRevoked   EventType = "USER_AUTHORIZATION_REVOKED"
	EventClientTokensRevokedAll     EventType = "CLIENT_TOKENS_REVOKED_ALL" //nolint:gosec // G101: false positive, this is a const string describing an event type, not a credential

	// Client Credentials Flow events (RFC 6749 §4.4)
	EventClientCredentialsTokenIssued EventType = "CLIENT_CREDENTIALS_TOKEN_ISSUED" //nolint:gosec // G101: false positive

	// Audit events
	EventTypeAuditLogView     EventType = "AUDIT_LOG_VIEWED"
	EventTypeAuditLogExported EventType = "AUDIT_LOG_EXPORTED"
)

// EventSeverity represents the severity level of an audit event
type EventSeverity string

const (
	SeverityInfo     EventSeverity = "INFO"
	SeverityWarning  EventSeverity = "WARNING"
	SeverityError    EventSeverity = "ERROR"
	SeverityCritical EventSeverity = "CRITICAL"
)

// ResourceType represents the type of resource being operated on
type ResourceType string

const (
	ResourceUser          ResourceType = "USER"
	ResourceClient        ResourceType = "CLIENT"
	ResourceToken         ResourceType = "TOKEN"
	ResourceDeviceCode    ResourceType = "DEVICE_CODE"
	ResourceOAuthConfig   ResourceType = "OAUTH_CONFIG"
	ResourceAuthorization ResourceType = "AUTHORIZATION"
)

// AuditDetails stores additional event-specific information as JSON
type AuditDetails map[string]any

// Value implements the driver.Valuer interface for database storage
func (a AuditDetails) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil //nolint:nilnil // nil driver.Value represents SQL NULL, which is valid here
	}
	return json.Marshal(a)
}

// Scan implements the sql.Scanner interface for database retrieval
func (a *AuditDetails) Scan(value any) error {
	if value == nil {
		*a = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal AuditDetails value: %v", value)
	}

	result := make(AuditDetails)
	if err := json.Unmarshal(bytes, &result); err != nil {
		return err
	}

	*a = result
	return nil
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID string `gorm:"primaryKey;type:varchar(36)" json:"id"`

	// Event information
	EventType EventType     `gorm:"type:varchar(50);index;not null" json:"event_type"`
	EventTime time.Time     `gorm:"index;not null"                  json:"event_time"`
	Severity  EventSeverity `gorm:"type:varchar(20);not null"       json:"severity"`

	// Actor information
	ActorUserID   string `gorm:"type:varchar(36);index" json:"actor_user_id"`
	ActorUsername string `gorm:"type:varchar(100)"      json:"actor_username"`
	ActorIP       string `gorm:"type:varchar(45);index" json:"actor_ip"` // Support IPv6

	// Resource information
	ResourceType ResourceType `gorm:"type:varchar(50);index" json:"resource_type"`
	ResourceID   string       `gorm:"type:varchar(36);index" json:"resource_id"`
	ResourceName string       `gorm:"type:varchar(255)"      json:"resource_name"`

	// Operation details
	Action       string       `gorm:"type:varchar(255);not null" json:"action"`
	Details      AuditDetails `gorm:"type:json"                  json:"details"`
	Success      bool         `gorm:"index;not null"             json:"success"`
	ErrorMessage string       `gorm:"type:text"                  json:"error_message,omitempty"`

	// Request metadata
	UserAgent     string `gorm:"type:varchar(500)" json:"user_agent,omitempty"`
	RequestPath   string `gorm:"type:varchar(500)" json:"request_path,omitempty"`
	RequestMethod string `gorm:"type:varchar(10)"  json:"request_method,omitempty"`

	// Timestamps (no UpdatedAt - immutable logs)
	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
}

// TableName specifies the table name for GORM
func (AuditLog) TableName() string {
	return "audit_logs"
}
