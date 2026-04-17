package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/util"
)

// Errors returned by JWKSFetcher.
var (
	ErrJWKSFetchFailed = errors.New("failed to fetch JWKS")
	ErrJWKSTooLarge    = errors.New("JWKS response exceeds size limit")
)

// Maximum JWKS body size accepted over the network (defense against slowloris / huge responses).
const jwksMaxBodyBytes = 1 << 20 // 1 MiB

// Minimum interval between forced refreshes of the same JWKS URI.
// Prevents attackers from triggering unbounded refetches by sending assertions
// with unknown kids — legitimate rotations still succeed after this cooldown.
const jwksRefreshCooldown = 30 * time.Second

// JWKSFetcher retrieves and caches JWK Sets from remote jwks_uri endpoints.
// It is safe for concurrent use.
type JWKSFetcher struct {
	httpClient *http.Client
	cache      core.Cache[util.JWKSet]
	ttl        time.Duration

	// lastRefresh tracks when each uri was last force-refreshed so kid-miss
	// driven refetches respect jwksRefreshCooldown.
	lastRefresh sync.Map // map[string]time.Time
}

// NewJWKSFetcher constructs a JWKSFetcher.
// timeout controls the HTTP request timeout; ttl controls the cache lifetime
// when a cache is provided. cache may be nil, in which case every call goes
// straight to the remote — callers that need kid-miss refresh semantics
// should supply a non-nil cache.
func NewJWKSFetcher(cache core.Cache[util.JWKSet], timeout, ttl time.Duration) *JWKSFetcher {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &JWKSFetcher{
		httpClient: &http.Client{Timeout: timeout},
		cache:      cache,
		ttl:        ttl,
	}
}

// Get returns the cached JWKS for uri, fetching it on cache miss. Use
// GetWithRefresh when verifying a signature against a specific kid so that a
// cache stale against a rotated signing key triggers a fresh fetch.
func (f *JWKSFetcher) Get(ctx context.Context, uri string) (*util.JWKSet, error) {
	return f.getCached(ctx, uri)
}

// GetWithRefresh returns the JWKS for uri. If the cached version does not
// contain a key with the requested kid, the cache is bypassed and the
// document is refetched — this supports runtime key rotation without waiting
// for the TTL to expire. Refreshes for the same uri are rate-limited to
// prevent malformed or attacker-crafted kids from triggering unbounded
// refetches of the remote endpoint.
func (f *JWKSFetcher) GetWithRefresh(ctx context.Context, uri, kid string) (*util.JWKSet, error) {
	set, err := f.getCached(ctx, uri)
	if err != nil {
		return nil, err
	}
	if kid == "" || set.FindByKid(kid) != nil {
		return set, nil
	}
	// With no cache there is nothing to refresh — getCached already dialed
	// the remote for this call, so an additional fetch is pure overhead.
	if f.cache == nil {
		return set, nil
	}
	prev, stored, ok := f.tryReserveRefresh(uri)
	if !ok {
		return set, nil
	}
	// Bypass the cache: fetch fresh directly and best-effort update the
	// cache afterward. This keeps key rotation working even if the cache
	// backend is degraded and Delete/Set fails — callers still see the
	// freshly rotated keys.
	fresh, err := f.fetch(ctx, uri)
	if err != nil {
		// Roll back the reservation so the next caller can retry, rather
		// than being suppressed by the cooldown after a transient error.
		f.rollbackRefreshReservation(uri, prev, stored)
		return nil, err
	}
	if setErr := f.cache.Set(ctx, uri, fresh, f.ttl); setErr != nil {
		log.Printf("[JWKSFetcher] cache set after refresh failed for %s: %v", uri, setErr)
		// Best-effort delete: without it the stale cached JWKS would
		// keep being returned until the cooldown expires, since
		// subsequent callers skip refresh while lastRefresh is fresh.
		if delErr := f.cache.Delete(ctx, uri); delErr != nil {
			log.Printf(
				"[JWKSFetcher] cache delete after failed refresh set failed for %s: %v",
				uri, delErr,
			)
		}
	}
	return &fresh, nil
}

// tryReserveRefresh attempts to reserve a refresh for uri, subject to the
// per-URI cooldown. LoadOrStore + CompareAndSwap together ensure that at most
// one concurrent caller wins the right to refresh once the cooldown has
// elapsed. On success it returns the previous timestamp (zero when the uri
// was never refreshed) and the timestamp it stored, so rollbackRefreshReservation
// can undo the reservation if the subsequent network fetch fails.
func (f *JWKSFetcher) tryReserveRefresh(uri string) (prev, stored time.Time, ok bool) {
	for {
		now := time.Now()
		existing, loaded := f.lastRefresh.LoadOrStore(uri, now)
		if !loaded {
			// First-ever reservation for this uri.
			return time.Time{}, now, true
		}
		prevTime := existing.(time.Time)
		if now.Sub(prevTime) < jwksRefreshCooldown {
			return time.Time{}, time.Time{}, false
		}
		// CompareAndSwap ensures only one concurrent caller wins the
		// post-cooldown refresh decision; losers retry the loop and fall
		// back into the cooldown branch.
		if f.lastRefresh.CompareAndSwap(uri, prevTime, now) {
			return prevTime, now, true
		}
	}
}

// rollbackRefreshReservation reverts a reservation made by tryReserveRefresh
// after the refresh fetch failed. Without this, a transient fetch error would
// strand key rotation until the cooldown elapses.
func (f *JWKSFetcher) rollbackRefreshReservation(uri string, prev, stored time.Time) {
	if prev.IsZero() {
		// Best-effort: if someone else updated since, leave their value alone.
		f.lastRefresh.CompareAndDelete(uri, stored)
		return
	}
	f.lastRefresh.CompareAndSwap(uri, stored, prev)
}

func (f *JWKSFetcher) getCached(ctx context.Context, uri string) (*util.JWKSet, error) {
	if f.cache == nil {
		set, err := f.fetch(ctx, uri)
		if err != nil {
			return nil, err
		}
		return &set, nil
	}
	set, err := f.cache.GetWithFetch(ctx, uri, f.ttl,
		func(ctx context.Context, _ string) (util.JWKSet, error) {
			return f.fetch(ctx, uri)
		})
	if err != nil {
		return nil, err
	}
	return &set, nil
}

func (f *JWKSFetcher) fetch(ctx context.Context, uri string) (util.JWKSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return util.JWKSet{}, fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	// RFC 7517 §8.5 defines application/jwk-set+json; many JWKS endpoints
	// honour Accept strictly and would 406 on plain application/json alone.
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return util.JWKSet{}, fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return util.JWKSet{}, fmt.Errorf(
			"%w: unexpected status %d", ErrJWKSFetchFailed, resp.StatusCode,
		)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBodyBytes+1))
	if err != nil {
		return util.JWKSet{}, fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	if len(body) > jwksMaxBodyBytes {
		return util.JWKSet{}, ErrJWKSTooLarge
	}
	set, err := util.ParseJWKSet(string(body))
	if err != nil {
		return util.JWKSet{}, fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	return *set, nil
}
