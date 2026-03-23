package store

import (
	"errors"
	"strings"
)

var (
	// ErrUsernameConflict is returned when a username already exists
	ErrUsernameConflict = errors.New("username already exists")

	// ErrAuthCodeAlreadyUsed is returned by MarkAuthorizationCodeUsed when the
	// code was already consumed by a concurrent request (0 rows updated).
	ErrAuthCodeAlreadyUsed = errors.New("authorization code already used")
)

// isUniqueConstraintError checks if the error is a database unique constraint violation.
// Works for both SQLite ("UNIQUE constraint failed") and PostgreSQL ("duplicate key value
// violates unique constraint").
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key")
}
