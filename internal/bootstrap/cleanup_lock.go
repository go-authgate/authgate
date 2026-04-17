package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidislock"

	"github.com/go-authgate/authgate/internal/config"
)

// Lock names for the distributed cleanup jobs. Keep in sync with docs/runbooks
// that may reference these keys for debugging stuck cleanups.
const (
	cleanupLockAuditLogs     = "cleanup:audit-logs"
	cleanupLockExpiredTokens = "cleanup:expired-tokens"
)

// initializeCleanupLocker builds a Redis-backed distributed locker that
// serializes periodic cleanup jobs across multi-pod deployments. Returns
// (nil, nil) when cleanup lock is disabled; callers treat a nil locker as
// "run unconditionally" (single-instance mode).
//
// KeyMajority is 1 (single Redis target) rather than a Redlock quorum. A
// Redis failover window could allow two pods to hold the lock simultaneously,
// but cleanup DELETEs are idempotent (the inner SELECT finds no matching rows
// on the second pod), so this is safe — the worst case is transient double
// work, never data loss or corruption.
func initializeCleanupLocker(cfg *config.Config) (rueidislock.Locker, error) {
	if !cfg.EnableCleanupLock {
		return nil, nil //nolint:nilnil // locker not needed when feature is disabled
	}
	if cfg.RedisAddr == "" {
		return nil, errors.New("ENABLE_CLEANUP_LOCK requires REDIS_ADDR to be set")
	}

	locker, err := rueidislock.NewLocker(rueidislock.LockerOption{
		ClientOption: rueidis.ClientOption{
			InitAddress: []string{cfg.RedisAddr},
			Password:    cfg.RedisPassword,
			SelectDB:    cfg.RedisDB,
		},
		KeyPrefix:   "authgate:lock",
		KeyMajority: 1,
		KeyValidity: cfg.CleanupLockKeyValidity,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cleanup locker: %w", err)
	}

	log.Printf("Cleanup lock initialized (validity: %v)", cfg.CleanupLockKeyValidity)
	return locker, nil
}

// runWithCleanupLock executes fn while holding the named distributed lock.
// When locker is nil (single-instance mode) fn runs unconditionally.
// When another pod currently holds the lock, fn is skipped silently and
// nil is returned — the next tick will try again.
func runWithCleanupLock(
	ctx context.Context,
	locker rueidislock.Locker,
	name string,
	fn func(context.Context) error,
) error {
	if locker == nil {
		return fn(ctx)
	}
	lockCtx, cancel, err := locker.TryWithContext(ctx, name)
	if err != nil {
		if errors.Is(err, rueidislock.ErrNotLocked) {
			return nil
		}
		return fmt.Errorf("acquire cleanup lock %q: %w", name, err)
	}
	defer cancel()
	return fn(lockCtx)
}
