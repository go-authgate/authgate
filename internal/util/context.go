package util

import (
	"context"
)

// contextKey is a private type to prevent key collisions in context
type contextKey int

const (
	contextKeyClientIP contextKey = iota
)

// SetIPContext embeds client IP into a standard context
func SetIPContext(ctx context.Context, ip string) context.Context {
	if ip != "" {
		return context.WithValue(ctx, contextKeyClientIP, ip)
	}
	return ctx
}

// GetIPFromContext extracts the client IP address from the context.
// Returns empty string if IP cannot be determined.
func GetIPFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value(contextKeyClientIP).(string); ok {
		return ip
	}
	return ""
}
