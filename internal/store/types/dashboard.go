package types

// DashboardCounts holds pre-aggregated counts for the admin dashboard,
// fetched in a single raw SQL query using scalar subselects.
type DashboardCounts struct {
	TotalUsers          int64 `gorm:"column:total_users"`
	AdminUsers          int64 `gorm:"column:admin_users"`
	DisabledUsers       int64 `gorm:"column:disabled_users"`
	TotalClients        int64 `gorm:"column:total_clients"`
	ActiveClients       int64 `gorm:"column:active_clients"`
	PendingClients      int64 `gorm:"column:pending_clients"`
	ActiveAccessTokens  int64 `gorm:"column:active_access_tokens"`
	ActiveRefreshTokens int64 `gorm:"column:active_refresh_tokens"`
}
