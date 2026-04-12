-- Phase 1 index additions for AuthGate performance at 20k+ user scale.
--
-- Usage notes
--   * PostgreSQL only. Run each statement individually; CREATE INDEX
--     CONCURRENTLY cannot run inside a transaction block.
--   * Safe to re-run: `IF NOT EXISTS` short-circuits when indexes already exist.
--   * AutoMigrate in internal/store/sqlite.go will create equivalent indexes on
--     fresh databases via GORM tags; this file is only needed for existing
--     production databases where CONCURRENTLY is required to avoid write locks.

-- oauth_applications: owner lookups and status filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_oauth_app_user_id
    ON oauth_applications (user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_oauth_app_status
    ON oauth_applications (status);

-- user_authorizations: ListUserAuthorizations / RevokeAllUserAuthorizationsByClientID
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_active
    ON user_authorizations (user_id, is_active);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_client_active
    ON user_authorizations (client_id, is_active);

-- oauth_connections: GetOAuthConnectionsByUserID / DeleteOAuthConnectionsByUserID
-- are served by the existing unique composite index idx_oauth_user_provider
-- (user_id, provider); PostgreSQL uses the leading column for user_id-only
-- predicates, so no standalone user_id index is required.

-- audit_logs: admin filter combinations
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_severity
    ON audit_logs (severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_type_time
    ON audit_logs (event_type, event_time DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_actor_time
    ON audit_logs (actor_user_id, event_time DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_resource_time
    ON audit_logs (resource_type, resource_id, event_time DESC);

-- device_codes: CountPendingDeviceCodes / pending polling lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_auth_exp
    ON device_codes (authorized, expires_at);

-- authorization_codes: cleanup and replay-prevention queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_authcode_used_exp
    ON authorization_codes (used_at, expires_at);
