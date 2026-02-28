package services

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authgate/authgate/internal/cache"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spyCache wraps a MemoryCache and counts Get/Set/GetWithFetch calls for test assertions.
type spyCache struct {
	inner          *cache.MemoryCache[models.User]
	getCalls       atomic.Int64
	setCalls       atomic.Int64
	withFetchCalls atomic.Int64
}

func newSpyCache() *spyCache {
	return &spyCache{inner: cache.NewMemoryCache[models.User]()}
}

func (s *spyCache) Get(ctx context.Context, key string) (models.User, error) {
	s.getCalls.Add(1)
	return s.inner.Get(ctx, key)
}

func (s *spyCache) Set(
	ctx context.Context,
	key string,
	value models.User,
	ttl time.Duration,
) error {
	s.setCalls.Add(1)
	return s.inner.Set(ctx, key, value, ttl)
}

func (s *spyCache) MGet(ctx context.Context, keys []string) (map[string]models.User, error) {
	return s.inner.MGet(ctx, keys)
}

func (s *spyCache) MSet(
	ctx context.Context,
	values map[string]models.User,
	ttl time.Duration,
) error {
	return s.inner.MSet(ctx, values, ttl)
}

func (s *spyCache) Delete(ctx context.Context, key string) error {
	return s.inner.Delete(ctx, key)
}

func (s *spyCache) Close() error {
	return s.inner.Close()
}

func (s *spyCache) Health(ctx context.Context) error {
	return s.inner.Health(ctx)
}

func (s *spyCache) GetWithFetch(
	ctx context.Context,
	key string,
	ttl time.Duration,
	fetchFunc func(ctx context.Context, key string) (models.User, error),
) (models.User, error) {
	s.withFetchCalls.Add(1)
	if value, err := s.Get(ctx, key); err == nil {
		return value, nil
	}
	value, err := fetchFunc(ctx, key)
	if err != nil {
		var zero models.User
		return zero, err
	}
	_ = s.Set(ctx, key, value, ttl)
	return value, nil
}

func newUserServiceWithStore(db *store.Store, c cache.Cache[models.User]) *UserService {
	return NewUserService(db, nil, nil, AuthModeLocal, false, nil, c, 5*time.Minute)
}

func makeTestUser(t *testing.T, db *store.Store) *models.User {
	t.Helper()
	u := &models.User{
		ID:           uuid.New().String(),
		Username:     "testuser-" + uuid.New().String()[:8],
		Email:        uuid.New().String() + "@example.com",
		PasswordHash: "hash",
		Role:         "user",
		AuthSource:   AuthModeLocal,
	}
	require.NoError(t, db.CreateUser(u))
	return u
}

func TestGetUserByID_CacheMiss(t *testing.T) {
	db := setupTestStore(t)
	spy := newSpyCache()
	svc := newUserServiceWithStore(db, spy)
	u := makeTestUser(t, db)

	result, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, result.ID)
	assert.Equal(t, u.Username, result.Username)

	// First call: one Get (miss) + one Set (populate cache)
	assert.Equal(t, int64(1), spy.getCalls.Load(), "expected one Get call on cache miss")
	assert.Equal(t, int64(1), spy.setCalls.Load(), "expected one Set call to populate cache")
}

func TestGetUserByID_CacheHit(t *testing.T) {
	db := setupTestStore(t)
	spy := newSpyCache()
	svc := newUserServiceWithStore(db, spy)
	u := makeTestUser(t, db)

	// First call populates cache
	first, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, first.ID)

	// Reset spy counts to isolate second call
	spy.getCalls.Store(0)
	spy.setCalls.Store(0)

	// Second call should be served from cache
	second, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, second.ID)

	assert.Equal(t, int64(1), spy.getCalls.Load(), "expected one Get call on cache hit")
	assert.Equal(t, int64(0), spy.setCalls.Load(), "expected no Set call on cache hit")
}

func TestGetUserByID_CacheInvalidation(t *testing.T) {
	db := setupTestStore(t)
	spy := newSpyCache()
	svc := newUserServiceWithStore(db, spy)
	u := makeTestUser(t, db)

	// Populate cache
	_, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)

	// Invalidate
	svc.InvalidateUserCache(u.ID)

	// Reset spy counts
	spy.getCalls.Store(0)
	spy.setCalls.Store(0)

	// Next call should re-fetch from DB (cache miss after invalidation)
	result, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, result.ID)

	assert.Equal(
		t,
		int64(1),
		spy.getCalls.Load(),
		"expected one Get call after invalidation (cache miss)",
	)
	assert.Equal(
		t,
		int64(1),
		spy.setCalls.Load(),
		"expected one Set call to repopulate cache after invalidation",
	)
}

func TestGetUserByID_ErrUserNotFound(t *testing.T) {
	db := setupTestStore(t)
	spy := newSpyCache()
	svc := newUserServiceWithStore(db, spy)

	_, err := svc.GetUserByID(uuid.New().String())
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestGetUserByID_UsesGetWithFetch(t *testing.T) {
	db := setupTestStore(t)
	spy := newSpyCache()
	svc := newUserServiceWithStore(db, spy)
	u := makeTestUser(t, db)

	result, err := svc.GetUserByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, result.ID)

	assert.Equal(t, int64(1), spy.withFetchCalls.Load(), "expected GetWithFetch to be called")
}
