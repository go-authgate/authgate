package models

import "time"

// UserAuthorization records a user's consent grant to an OAuth application.
// There is at most one active record per (UserID, ApplicationID) pair — the
// most recent SaveUserAuthorization call for that pair upserts (overwrites)
// any prior consent. Tokens issued under earlier consents retain their
// AuthorizationID FK to the (now-overwritten) record so cascade-revoke from
// /account/authorizations still functions; the listing UI shows the
// LATEST consent.
type UserAuthorization struct {
	ID   uint   `gorm:"primaryKey;autoIncrement"`
	UUID string `gorm:"uniqueIndex;size:36;not null"` // Public UUID for API/UI identification

	// Relations (composite unique index ensures one grant per user+app)
	UserID        string `gorm:"not null;uniqueIndex:idx_user_app"` // FK → User.ID
	ApplicationID int64  `gorm:"not null;uniqueIndex:idx_user_app"` // FK → OAuthApplication.ID
	ClientID      string `gorm:"not null;index"`                    // Denormalized ClientID UUID (for UI display and API responses)

	Scopes string `gorm:"not null"`
	// Resource holds the RFC 8707 Resource Indicator(s) the user approved
	// at consent time. The remembered-consent shortcut on /oauth/authorize
	// requires an EXACT resource-set match before auto-approving — a
	// no-resource request must not be silently approved off a resource-bound
	// consent (or vice versa), since the user only ever consented to a
	// specific audience binding. Empty means "no resource was approved"
	// (i.e. the access token will fall back to the static JWT_AUDIENCE).
	Resource  StringArray `gorm:"type:json"`
	GrantedAt time.Time
	RevokedAt *time.Time
	IsActive  bool `gorm:"not null;default:true"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (UserAuthorization) TableName() string {
	return "user_authorizations"
}
