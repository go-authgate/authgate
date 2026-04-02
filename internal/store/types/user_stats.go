package types

// UserStatsCounts holds aggregate counts for a user's related records.
type UserStatsCounts struct {
	ActiveTokenCount         int64
	OAuthConnectionCount     int64
	ActiveAuthorizationCount int64
}
