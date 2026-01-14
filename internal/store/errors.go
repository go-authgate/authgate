package store

import "errors"

var (
	// ErrUsernameConflict is returned when a username already exists
	ErrUsernameConflict = errors.New("username already exists")

	// ErrRecordNotFound wraps GORM's not found error for consistency
	ErrRecordNotFound = errors.New("record not found")
)
