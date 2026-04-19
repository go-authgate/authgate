package store

import "errors"

var (
	// ErrUsernameConflict is returned when a username already exists
	ErrUsernameConflict = errors.New("username already exists")

	// ErrExternalUserMissingIdentity is returned by UpsertExternalUser when
	// the upstream provider supplied a whitespace-only (or empty) username or
	// email. Without a stable identity we cannot safely create or link a user.
	ErrExternalUserMissingIdentity = errors.New("external user missing username or email")

	// ErrAuthCodeAlreadyUsed is returned by MarkAuthorizationCodeUsed when the
	// code was already consumed by a concurrent request (0 rows updated).
	ErrAuthCodeAlreadyUsed = errors.New("authorization code already used")

	// ErrDeviceCodeAlreadyAuthorized is returned by AuthorizeDeviceCode when the
	// device code was already authorized by a concurrent request (0 rows updated).
	ErrDeviceCodeAlreadyAuthorized = errors.New("device code already authorized")
)
