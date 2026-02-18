package models

import "time"

// UserAuthorization records a user's consent grant to an OAuth application.
// There is at most one active record per (UserID, ApplicationID) pair.
type UserAuthorization struct {
	ID   uint   `gorm:"primaryKey;autoIncrement"`
	UUID string `gorm:"uniqueIndex;size:36;not null"` // 對外 API/UI 識別碼

	// Relations (composite unique index ensures one grant per user+app)
	UserID        string `gorm:"not null;uniqueIndex:idx_user_app"` // FK → User.ID
	ApplicationID int64  `gorm:"not null;uniqueIndex:idx_user_app"` // FK → OAuthApplication.ID
	ClientID      string `gorm:"not null;index"`                    // Denormalized ClientID UUID (for UI display and API responses)

	Scopes    string `gorm:"not null"`
	GrantedAt time.Time
	RevokedAt *time.Time
	IsActive  bool `gorm:"not null;default:true"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (UserAuthorization) TableName() string {
	return "user_authorizations"
}
