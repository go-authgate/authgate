package util

import (
	"context"
)

// contextKey is a private type to prevent key collisions in context
type contextKey int

const (
	contextKeyClientIP contextKey = iota
	contextKeyUserAgent
	contextKeyRequestPath
	contextKeyRequestMethod
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

// SetRequestMetadataContext embeds HTTP request metadata into a standard context.
func SetRequestMetadataContext(
	ctx context.Context,
	userAgent, path, method string,
) context.Context {
	ctx = context.WithValue(ctx, contextKeyUserAgent, userAgent)
	ctx = context.WithValue(ctx, contextKeyRequestPath, path)
	ctx = context.WithValue(ctx, contextKeyRequestMethod, method)
	return ctx
}

// GetUserAgentFromContext extracts the User-Agent from the context.
func GetUserAgentFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKeyUserAgent).(string); ok {
		return v
	}
	return ""
}

// GetRequestPathFromContext extracts the request path from the context.
func GetRequestPathFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKeyRequestPath).(string); ok {
		return v
	}
	return ""
}

// GetRequestMethodFromContext extracts the HTTP method from the context.
func GetRequestMethodFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKeyRequestMethod).(string); ok {
		return v
	}
	return ""
}
