package models

import (
	"context"
)

// contextKey is a private type to prevent key collisions in context
type contextKey int

const (
	contextKeyUser contextKey = iota
)

// SetUserContext embeds user object into a standard context
func SetUserContext(ctx context.Context, user *User) context.Context {
	if user != nil {
		return context.WithValue(ctx, contextKeyUser, user)
	}
	return ctx
}

// GetUsernameFromContext extracts the username from the user object in context.
// Returns empty string if user cannot be determined.
func GetUsernameFromContext(ctx context.Context) string {
	if user, ok := ctx.Value(contextKeyUser).(*User); ok && user != nil {
		return user.Username
	}
	return ""
}

// GetUserIDFromContext extracts user ID from context
func GetUserIDFromContext(ctx context.Context) string {
	if user, ok := ctx.Value(contextKeyUser).(*User); ok && user != nil {
		return user.ID
	}
	return ""
}

// GetUserFromContext extracts full user object from context
func GetUserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(contextKeyUser).(*User); ok {
		return user
	}
	return nil
}
